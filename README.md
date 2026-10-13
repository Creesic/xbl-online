# XB Online for xboxrecomp

Sign in with your Insignia login on [xb.live](https://xb.live). That account is what you play with on XB Online. Insignia support is coming soon.

This is a library a recompiled game links. It is not part of [xboxrecomp](https://github.com/sp00nznet/xboxrecomp). Clone that toolkit on its own and pull it whenever it updates. Do not copy this code into it.

## What the game sees

xboxrecomp already turns `\Device\Harddisk0\Partition0` into `Partition0.img` in the save directory. This library writes the Xbox Live account into that image, at the config sectors retail games read (physical LBA 8 plus the config index). The game's own `XOnlineGetUsers` then lists the gamertag. The XBE is not patched.

## Sign-in

Temporarily disabled while the account flow is reworked: the sign-in page does
not open at launch, and F10/L3+R3 do not open it. Console identity and saved
account installation remain active. The flow below describes the retained UI
for when it is enabled again.

Nothing opens at launch. On Windows, press F10 or both stick clicks (L3+R3) to open the sign-in page on this computer. Sign in with the same Insignia login you use on xb.live:

- Scan the QR code. It opens `https://xb.live/link?code=...`. Approve it while signed into xb.live with that Insignia login. The page then downloads the XB Online account into `Partition0.img`.
- Or type that same email and password on the page.

Back out of the game's account list and open it again. You are on XB Online. Insignia support is coming soon.

The address is also printed as `[xbl] Sign in at ...`.

The first launch makes a console identity for this PC and keeps it: a 12-digit serial, a MAC address, a hard-drive key, and an online key, plus the MACS key derived from those two keys. Sign-in sends that identity to XB Online, and the hard-drive key is the one the game reads when it checks the account. It is stored in `~/Library/Application Support/XBOnline` on macOS and `%LOCALAPPDATA%\XBOnline` on Windows (`console.txt` and `eeprom.bin`). The disk image stays in xboxrecomp's save directory, which by default is `%LOCALAPPDATA%\xboxrecomp` or `~/.local/share/xboxrecomp`.

## Attach a game

Clone this repo next to the game. In the game's `CMakeLists.txt`, after the executable exists:

```cmake
include(${CMAKE_CURRENT_SOURCE_DIR}/../xbl-online/cmake/XblOnline.cmake)
xbl_online_link(your_game_target)
```

Adjust the path so it points at this repo's `cmake/XblOnline.cmake`. No change to xboxrecomp is required, and the game's `main.c` does not need an edit when it uses the toolkit's default save directory.

If `xbox_path_init` is called with a different save directory, set `XBL_ONLINE_SAVE_DIR` to that same path before the game starts, or call `xbl_online_attach(save_dir)` after `xbox_path_init`.

`XBL_ONLINE_DISABLE=1` turns the library off. `XBL_ONLINE_PROVISION_URL` overrides the XB Online provision host (default `https://online.xb.live/api/v1/provision`).
