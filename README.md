[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)  [![Gitter](https://badges.gitter.im/cesanta/mongoose-os.svg)](https://gitter.im/cesanta/mongoose-os?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

# WiFi setup library for Mongoose OS

Web-based WiFi setup using Mongoose OS RPC service. Designed for `ESP8266` and `ESP32` platforms

# Install

Add this dependency in your app's `mos.yml`

```yaml
libs:
  - origin: https://github.com/d4rkmen/wifi-setup
```

# Filesystem

Files list added to filesystem:

* `favicon.ico` - default Mongoose OS icon, for the case app not have icon
* `logo.png` - default Mongoose OS logo, for the case app not have logo
* `save.html` - the captive portall `Success` page
* `wifi.html` - the captive portal landing page, leaving `index.html` for Your app

# Demo app

The [demo-c](https://github.com/mongoose-os-apps/demo-c) app WiFi setup flow

![](https://github.com/d4rkmen/wifi-setup/blob/master/docs/wifi-setup.gif)

# Copyrights

Myles McNamara <https://smyl.es> (captive portal)

Cesanta Software Limited (Scan)
