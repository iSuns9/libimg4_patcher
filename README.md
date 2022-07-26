# libimg4_patcher
A tool for patching a 64-bit libimg4.dylib binary to allow for improperly signed img4 images to be accepted during a restore

## Build
`make`

## Usage
1. Extract binary from an iOS ramdisk (macOS only):
    - `img4 -i <ramdisk> -o ramdisk.dmg`
        - `img4` can be found [here](https://github.com/xerub/img4lib)
    - `hdiutil attach ramdisk.dmg -mountpoint ramdisk`
    - `cp ramdisk/usr/lib/libimg4.dylib .`
    - `hdiutil detach ramdisk`

2. Run `libimg4_patcher`:
    - `libimg4_patcher libimg4.dylib libimg4.patched`

3. Resign patched restored_external binary
    - `ldid -S libimg4.patched`