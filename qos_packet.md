# RBX::Security QoS packets (v2.741.1061 arm64)

Everything below here is resolved **statically** with the APS2 relocation decoder and 
roblox ships the library with a zeroed `.dynsym` (no dynamic
symbols) and the `.rela.dyn` section replaced by a packed-relocation blob, so
every vtable / `std::function` slot in `.data.rel.ro` is zero in the file and
only becomes an address after decoding the APS2 stream and all addresses in this
document are file vaddrs == Ghidra addresses (image base 0).

## 0. The three QoS-related message types

| type (LE16 @ plaintext header **+0x0C**) | direction | produced / handled by |
|---|---|---|
| `0x040B` | server -> client | `RBX::Security::ClientQoSImplAndroid::platformOnServerCommand`: vtable slot **[18]** = `0x3f5ca74`, footer λ = `0x3f5d4a0` |
| `0x1DA6` | client -> server | QoS **result** message, built by the `submitTask` λ = `0x3f5e390` and sent with `FUN_03f5fbd0` |
| `0xA814` | client -> server | `RBX::Security::ClientQoSImpl::secureHeartbeat` λ = `0x3f63dec` |

The server->client QoS command also carries the constant `0x1048` at plaintext **+0x10** and the inbound dispatcher `FUN_03f5f50c` requires it (`sVar18 == 0x1048`) before it forwards the packet to virtual slot `+0x90` ( = method[18] = `platformOnServerCommand`).

The client->server messages carry `0xBA58` at the same +0x10 slot, `0x0001` at +0x0E, `0x02E5` (= 741, the build number) at +0x12 and `0x90F84D41` at +0x14 (constant tail `01 00 58 BA E5 02 41 4D F8 90` from +0x0E to +0x17).

## 1. SecurityChannel wire packet

### 1.1 Outbound (client -> server), built by `FUN_03f5fbd0(type, payload)`

Plaintext handed to the cipher:
```
+0x00  u64   message id            (FUN_03f629c8)
+0x08  u32   BE payload length + 0x20
+0x0C  u16   LE message type       (0x1DA6, 0xA814, …)  <-- the "opcode"
+0x0E  10    constant  01 00 58 BA E5 02 41 4D F8 90
+0x18  u64   session token          (FUN_02b94104)
+0x20  ...   payload
```
Then ChaCha20 record-encrypt (`FUN_03f62c10` init / `FUN_03f62ea0` encrypt / `FUN_03f62f68` tag) and wrap:
```
wire: [u64 id] [ciphertext(header||payload)]          (id written little-endian)
```
`FUN_03f5fbd0` returns `0x762a33f8` on success (Roblox uses hashed status codes everywhere instead of errno).

### 1.2 Inbound (server -> client), parsed by `FUN_03f5f50c`

```
+0x00  u64   id (read big-endian on the wire)
+0x08  u64   session/key material
+0x10  u64   session/key material  crypto context fields; +0x34/+0x28 are
+0x18  u64   session/key material   XOR-combined, +0x30 is a u32
+0x20  u64   session/key material
+0x28  u32   key id
+0x30  u32   .
+0x34  u32   .
+0x38  u32   .
+0x3C  ...   encrypted records (FUN_03f61664 decrypt + tag verify, looped)
```
Decrypted plaintext = the 32-byte header + payload:
```
+0x00  u64   id
+0x08  u32   BE declared length (> 0x1F)
+0x0C  u16   LE type  0x040B  (checked by the platformOnServerCommand λ)
+0x0E  u16   LE 0x0001
+0x10  u16   LE 0x1048        (checked by FUN_03f5f50c)
+0x12  u16   LE 0x02E5        (741 = client build)
+0x14  u32   LE 0x90F84D41
+0x18  u64   session token
+0x20  ...   payload, length = declared - 0x20
```

## 2. Packet A: QoS command (`platformOnServerCommand`)

### 2.1 Call chain

```
inbound record  --> FUN_03f5f50c (decrypt, require u16@+0x10 == 0x1048)
                     |  builds 32-byte header struct, calls vtable+0x90
                     v
   ClientQoSImplAndroid::platformOnServerCommand = 0x3f5ca74  (vtable[18])
      allocates a 0x58-byte __func object (FUN_01dfee94(0x58))
        +0x00 vptr = 0x663e9a0   (std::__function::__func vtable, see APS2.md)
        +0x08 header[0x00..0x08]  (u64 id)
        +0x10 header[0x08..0x10]  (u16 type == 0x040B + neighbours)  <-- gate
        +0x18 header[0x10..0x18]
        +0x20 header[0x18..0x20]
        +0x28 vector.begin / +0x30 vector.end / +0x38 vector.cap  (payload)
        +0x40 shared_ptr<AppQoSSession>.ptr / +0x48 .ctrl
        +0x50 this
      then schedules it (FUN_0245fbd0 + virtual dispatch)
                     v
   the λ runs on the DataModel thread = 0x3f5d4a0
      ├─ if header.u16@8 != 0x040B  -> skip parsing
      └─ parse payload:
           [u16 0xD84F][u16 kind][u32 BE v][v bytes section1][u32 BE w][w bytes section2]
      exact-length rule: len == 8 + v + 4 + w
      errors (hashed): 0x3f9ae005 (short), 0xfbba12ac (v overflow), 0x896aafd9,
                       0x986eb00d (w overflow), 0x1504ac1e (trailing), 0x65352618 (magic)
                     v
   FUN_03f5ccf0(ctx, out, kind, session, section1, v, section2, w)
      kind 0x0434 : sections used as-is
      kind 0x2F1B : both sections first run through FUN_02c6123c (transform)
      then section2 is parsed as a TLV list:
         [u32 BE tag][u32 BE len][len bytes value]
            tag 1 -> byte buffer        (64-byte signature in the observed path)
            tag 2 -> bool               (BE32 != 0)
            tag 3 -> u32                (time limit, compared against FUN_06398f28())
            tag 4 -> u32 (<< 0x14)
            tag 5 -> second byte buffer
      then builds a 0xB8-byte task object and spawns a thread:
         pthread_create(…, FUN_03f5d74c, task)
                     v
   worker FUN_03f5d74c  (status codes 0x2000..0x200B)
      ├─ tag-2 bool == 0 -> run module path, else time-window path
      |     (0x2001/0x2002 = deadline checks)
      ├─ requires tag-1 buffer length == 0x40 and verifies a 64-byte signature
      |     thunk_FUN_0250f678(sig, payload, len, key @ 0x8508f6)  -> 0 = pass
      |     (fails -> status 0x2005)
      ├─ writes the payload to a temp file, dlopen()s it, dlsym()s one export,
      |  calls it with (payload fields) and collects the returned buffer
      |     fopen fail 0x2008 / fwrite fail 0x2009 / dlopen 0x200A / dlsym 0x200B
      └─ result is delivered back through the session object
```

### 2.2 Body summary

```
offset  size  field
 0      2     magic 0xD84F (BE, bytes D8 4F)
 2      2     kind: 0x0434 (plain) | 0x2F1B (transformed sections)   [BE]
 4      4     v = length of section1 (BE)
 8      v     section1 - carries the 64-byte signature blob in the module path
 8+v    4     w = length of section2 (BE)
 12+v   w     section2 - TLV list (tags 1..5 above)
```
Total must equal `8 + v + 4 + w` exactly.

### 2.3 The result packet (`submitTask` path, type `0x1DA6`)

The `submitTask` λ (`0x3f5e390`) builds a JSON document and sends it as a
security packet of type **0x1DA6**:

```
JSON: { "status": <int>, "err": <string>, "output": <bytes> }
  "status"  = worker status code (0x2000..0x200B) or 0
  "err"     = error text ("" on success)
  "output"  = module output bytes
```
The JSON text is post-processed by `FUN_063e4828(..., 3, 0)` (3 = mode/level) and
wrapped in the same `0xD84F` envelope (magic bytes `D8 4F 04 34` = type 0x0434),
then handed to `FUN_03f5fbd0` with `type = 0x1DA6`, and the response is delivered
through the captured object (`FUN_02fe8f20`).

## 3. Hashed codes seen in this path (all little-endian u32s)

```
0x762a33f8  success
0x2000..0x200B  worker statuses (0x2005 bad signature, 0x200A dlopen, 0x200B dlsym)
0x986eb00d, 0x71dae9a0, 0x7f6d34ae   dispatcher / parse failures
0x3f9ae005, 0xfbba12ac, 0x896aafd9, 0x1504ac1e, 0x65352618  envelope validation
0xdbb52d40, 0xfa574a99, 0x2fc265bf, 0xebe25a15  submitTask path
0xb1eb30d6  heartbeat path
0x5cc82bbe  client-info (PSID/UUID) handler
```
