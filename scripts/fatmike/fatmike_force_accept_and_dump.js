// Fatmike Crackme dynamic trace helper
// Usage in Windows VM:
//   frida -f "C:\\path\\Crackme.exe" -l fatmike_validator_trace.js

(function () {
  var FORCE_ACCEPT = true; // set true to force validator success

  function getMainModule() {
    var m = Process.findModuleByName('Crackme.exe') || Process.findModuleByName('crackme.exe');
    if (m) return m;
    var mods = Process.enumerateModules();
    return mods.length ? mods[0] : null;
  }

  function safeReadAnsi(p) {
    try {
      if (!p || p.isNull()) return '<null>';
      var s = p.readAnsiString();
      return s === null ? '<nullstr>' : s;
    } catch (e) {
      return '<read_err>';
    }
  }

  function safeReadMsvcString(strObj) {
    try {
      if (!strObj || strObj.isNull()) return '<null-std-string>';
      var size = strObj.add(0x10).readU32();
      var cap = strObj.add(0x14).readU32();
      var dataPtr = cap <= 0x0f ? strObj : strObj.readPointer();
      if (size > 0x1000) return '<size-too-large:' + size + '>';
      if (dataPtr.isNull()) return '<null-data>';
      return dataPtr.readUtf8String(size);
    } catch (e) {
      return '<std-string-read-err>';
    }
  }

  function printHit(tag, obj) {
    try {
      send({ tag: tag, data: obj });
    } catch (_) {}
    console.log('[' + tag + '] ' + JSON.stringify(obj));
  }

  var m = getMainModule();
  if (!m) {
    console.log('[-] Could not identify main module');
    return;
  }

  var base = m.base;
  var validator = base.add(0x30a5); // FUN_004030A5
  var decryptOut = base.add(0x2876); // FUN_00402876

  console.log('[+] Module ' + m.name + ' @ ' + base);
  console.log('[+] validator  @ ' + validator);
  console.log('[+] decryptOut @ ' + decryptOut);
  console.log('[+] FORCE_ACCEPT=' + FORCE_ACCEPT);

  Interceptor.attach(validator, {
    onEnter: function (args) {
      this.serialPtr = args[0];
      this.serial = safeReadAnsi(this.serialPtr);
      this.thisPtr = this.context.ecx;
      printHit('validator_enter', {
        serial: this.serial,
        serial_ptr: this.serialPtr.toString(),
        this_ptr: this.thisPtr.toString()
      });
    },
    onLeave: function (retval) {
      var original = retval.toInt32() & 0xff;
      if (FORCE_ACCEPT) {
        retval.replace(ptr(1));
      }
      var finalVal = retval.toInt32() & 0xff;
      printHit('validator_leave', {
        serial: this.serial,
        retval_original: original,
        retval_final: finalVal,
        forced: FORCE_ACCEPT
      });
    }
  });

  Interceptor.attach(decryptOut, {
    onEnter: function (args) {
      this.outStrObj = args[0];
    },
    onLeave: function (retval) {
      var s = safeReadMsvcString(this.outStrObj);
      if (s && s.length > 0 && s !== '<std-string-read-err>') {
        printHit('decrypt_out', {
          text: s,
          len: s.length,
          maybe_flag: s.indexOf('CMO{') !== -1
        });
      }
    }
  });

  var msgBox = Module.findExportByName('user32.dll', 'MessageBoxA');
  if (msgBox) {
    Interceptor.attach(msgBox, {
      onEnter: function (args) {
        var text = safeReadAnsi(args[1]);
        var caption = safeReadAnsi(args[2]);
        printHit('msgbox', { caption: caption, text: text });
      }
    });
  }
})();
