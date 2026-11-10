# Native REALITY dependencies

The optional `native-reality` adapter links the following maintained upstream
implementations. Their source files have not been copied into Obsidian or
modified in place. Obsidian's original code retains its own license.

| Component | Pinned revision | License / source |
| --- | --- | --- |
| Xray-core | `676eaf66f8f05d4d558ee7a74b4736623d3feeb9` (v26.11.9) | [MPL-2.0](licenses/XRAY-MPL-2.0.txt), [source](https://github.com/XTLS/Xray-core/tree/676eaf66f8f05d4d558ee7a74b4736623d3feeb9) |
| REALITY | `4bb46b2afd8b` | [MPL-2.0](licenses/REALITY-MPL-2.0.txt), [Go BSD notice](licenses/REALITY-Go-BSD.txt), [source](https://github.com/XTLS/REALITY/tree/4bb46b2afd8b) |
| uTLS | `a13c59ffe98b` | [BSD notice](licenses/uTLS-BSD.txt), [source](https://github.com/refraction-networking/utls/tree/a13c59ffe98b) |

Exact module versions and checksums are recorded in `go.mod` / `go.sum`.
Redistributions must retain the applicable notices and satisfy the linked
licenses, including source availability for MPL-covered files. These notices
supplement the obligations for the other existing Go dependencies.

# Server TUN offloads

On Linux the server opens its TUN with segmentation offloads through the `tun` package of
wireguard-go (GSO split on read, GRO merge on write). The module is linked unmodified.

| Component | Pinned revision | License / source |
| --- | --- | --- |
| wireguard-go | `f333402bd9cb` | [MIT](licenses/wireguard-go-MIT.txt), [source](https://git.zx2c4.com/wireguard-go/tree/?id=f333402bd9cb) |

