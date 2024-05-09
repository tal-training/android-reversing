Java.perform(function () {
    // Find the desired class (replace 'com.example.MyActivity' with your actual package name and class name)
    const MyActivity = Java.use('com.example.MyActivity');
    
    // Define the onCreate() method signature (you may want to generate this automatically with JADX)
    const onCreateSignature = 'void onCreate(android.os.Bundle)';
    
    // Create an interceptor for the onCreate() method
    Interceptor.attach(MyActivity.prototype['onCreate'].implementation, {
        onEnter: function (args) {
            console.log("[*] Entering onCreate()");
            
            // Get the first argument passed to the method (the 'savedInstanceState' bundle)
            const savedInstanceState = args[0];
            
            // Access the second local variable declared within the onCreate() method (assuming it's named 'message')
            const message = this.message;
            
            // Modify the 'message' variable content (e.g., replace it with "Hello from Frida!")
            message = "Hello from Frida!";
            
            console.log(`[+] Changed 'message' variable to "${message}"`);
        },
        
        onLeave: function (retval) {
            console.log("[*] Leaving onCreate()");
        }
    });
});
