import frida
import sys

jscode = """
Java.perform(() => {
  const i = Java.use('Intrinsics');
  i.areEqual.overload('java.lang.String', 'java.lang.String').implementation=(value, defaultvalue) => {
        console.log("on_enter parameters", value, defaultvalue);
    };
});
"""
device = frida.get_usb_device()
session = device.attach(21950)
# session = device.attach(pid)
script = session.create_script(jscode)
script.load()
sys.stdin.read()
# device.resume(pid)
