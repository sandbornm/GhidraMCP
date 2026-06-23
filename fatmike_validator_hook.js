// Hook Crackme.exe validator function FUN_004030a5 (base + 0x30A5)
(function () {
  function pickModule() {
    var names = ["Crackme.exe", "crackme.exe"];
    for (var i = 0; i < names.length; i++) {
      var m = Process.findModuleByName(names[i]);
      if (m) return m;
    }
    return Process.enumerateModules()[0];
  }

  var m = pickModule();
  if (!m) {
    console.log("[-] Could not locate module");
    return;
  }

  var validator = m.base.add(0x30a5);
  console.log("[+] Module: " + m.name + " base=" + m.base);
  console.log("[+] Hooking validator @ " + validator + " (FUN_004030a5)");

  Interceptor.attach(validator, {
    onEnter: function (args) {
      this.serialPtr = args[0];
      this.thisPtr = this.context.ecx;
      this.serial = "<unreadable>";
      try {
        if (!this.serialPtr.isNull()) {
          this.serial = this.serialPtr.readAnsiString();
        }
      } catch (e) {
        this.serial = "<read error>";
      }
    },
    onLeave: function (retval) {
      var ok = (retval.toInt32() & 0xff) !== 0;
      send({
        event: "validator_return",
        serial: this.serial,
        serial_ptr: this.serialPtr.toString(),
        this_ptr: this.thisPtr.toString(),
        retval_raw: retval.toString(),
        accepted: ok
      });
      console.log("[validator] serial='" + this.serial + "' accepted=" + ok + " retval=" + retval);
    }
  });
})();
