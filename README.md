# modoru 戻る

*modoru* means "to go back" in Japanese and is a downgrader for the *PS Vita™*.

## Requirements

- Your device must already run HENkaku/h-encore on firmwares 3.60-3.68 in order to use this software. Firmwares 3.69 and 3.70 can use this software once a new hack is released.
- Your device's battery has be at least at 50%.

## Installation

1. Download and install [modoru.vpk](https://github.com/TheOfficialFloW/modoru/releases/download/v1.0/modoru.vpk) using *VitaShell*.
2. Obtain the `PSP2UPDAT.PUP` file of your desired firmware (make sure that this firmware is officially hackable) and place it at `ux0:app/MODORU000/PSP2UPDAT.PUP` (don't install `modoru.vpk` afterwards, otherwise the update file will be removed).
3. Disable all your plugins. Easiest way is renaming `ux0:tai` and `ur0:tai` to some other name.
4. Reboot your device and relaunch *HENkaku/h-encore*.
5. Launch the *modoru* application and follow the instructions on screen.
6. Enjoy the installation and welcome to your favourite firmware.

## FAQ

- Q: Where can I find and download firmwares?  
  A: Here is a nice collection by darthsternie: [PS Vita Firmwares](https://darthsternie.net/index.php/ps-vita-firmwares/). Make sure you download the firmware from the `Complete Official Firmwares` section.
- Q: There are 3 different PUP files in the archive, which one do I need?  
  A: There are packages with (pre), (systemdata) and (full). You should choose the full one.
- Q: Can I downgrade my 3.69/3.70 device using this tool?  
  A: Yes, but not yet. You'll need to wait until the next exploit chain is released.
- Q: My factory firmware is higher than 3.65 and *modoru* doesn't allow me to downgrade to 3.60/3.65.  
  A: Unfortunately, there are some devices with factory firmware above 3.65. These cannot be downgraded (yet). This means no bootloader hack for you.
- Q: Can I downgrade my device to 3.60/3.65 and then install ensō?  
  A: Yes, that's the main goal of this tool.
- Q: Can I downgrade my testkit/devkit?  
  A: It has not been tested yet, but you can very likely do it. You should even be able to go lower than firmware 1.692, which is officially inhibited.
- Q: How low can I downgrade?  
  A: You can go down to your factory firmware (this is highlighted in yellow within *modoru*).
- Q: Can I use this tool to update or reinstall my firmware?  
  A: Yes, you can downgrade, update or reinstall any firmware using this tool.
- Q: Is there a chance of bricking?  
  A: Not likely, since this application is using the official updater and only makes a few harmless patches to bypass some checks.

## Donation

If you like my work and want to support future projects, you can make a donation:

- via bitcoin `361jRJtjppd2iyaAhBGjf9GUCWnunxtZ49`
- via [paypal](https://www.paypal.me/flowsupport/20)
- via [patreon](https://www.patreon.com/TheOfficialFloW)

Thank you!

## Credits

- Thanks to Freakler for the LiveArea design.
- Thanks to liblor for the name suggestion.
- Thanks to yifanlu for prior research on downgrading.
- Thanks to molecule for SCE decryption utilities.
- Thanks to SKGleba for betatesting.

