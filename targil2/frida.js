Java.perform(() => {
    const i = Java.use('kotlin.jvm.internal.Intrinsics');
    i.areEqual.overload('java.lang.Object', 'java.lang.Object').implementation=(value, defaultvalue) => {
          console.log("on_enter parameters", value, defaultvalue);
          return true;  // for bypass auth
      };
  });