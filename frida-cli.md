*Frida on Android: A Command-Line Tutorial for Dynamic Analysis**

In this tutorial, we'll explore how to use Frida from the command line for
Android dynamic analysis. We'll focus on setting up Frida, attaching it to
an Android process, and executing commands.

**Prerequisites:**

1. **Frida**: Install Frida from the official GitHub repository or using 
your system's package manager (e.g., `brew install frida` on macOS).
2. **Android SDK**: Ensure you have the Android SDK installed and 
configured on your machine.
3. **ADB**: Make sure ADB (Android Debug Bridge) is properly set up and 
working.

**Step 1: Set up Frida**

To start using Frida from the command line, navigate to the directory 
where you installed Frida:

```bash
cd /path/to/frida/installation
```

Next, verify that Frida is correctly configured by running:

```bash
frida --version
```

This should display the Frida version.

**Step 2: Connect to Android Device**

Connect your Android device to your machine using a USB cable. Then, start
the ADB server:

```bash
adb start-server
```

**Step 3: List available devices and processes**

Use the following command to list all connected Android devices:

```bash
frida-pid --list-devices
```

Take note of the device's serial number (e.g., `ZYX1234567890`).

Next, use Frida to list the processes running on your Android device:

```bash
frida-ps -U -D ZYX1234567890 -A
```

This will display a list of processes. Note the process ID (PID) you're interested in attaching Frida to.

**Step 4: Attach Frida**

Use the following command to attach Frida to the target process:

```bash
frida-pid --attach ZYX1234567890 <PID>
```

Replace `<PID>` with the actual PID of the process you want to analyze. For example:

```bash
frida-pid --attach ZYX1234567890 1234
```

Frida will now attach itself to the target process and wait for commands.

**Step 5: Execute Frida commands**

Use Frida's built-in commands to inspect and manipulate the attached process. Some common commands include:

* **syscalls**: List system calls made by the process:
```bash
frida-pid -U -D ZYX1234567890 <PID> syscalls
```

* **steal_cookies**: Steal the cookies (session IDs) of the process:
```bash
frida-pid -U -D ZYX1234567890 <PID> steal_cookies
```

* **inject**: Inject a script into the process:
```bash
frida-pid -U -D ZYX1234567890 <PID> inject my_script.js
```

Replace `my_script.js` with your own JavaScript file.

**Step 6: Detach Frida**

When you're finished analyzing, use the following command to detach Frida from the process:

```bash
frida-pid -U -D ZYX1234567890 <PID> detach
```

This will release Frida's hold on the process.

**Conclusion:**

In this tutorial, we covered the basics of using Frida from the command line for Android dynamic analysis. You learned how to set up Frida, connect to an Android 
device, list processes and devices, attach Frida to a target process, execute commands, and detach Frida when finished.

Remember to always follow best practices for responsible security testing and ensure you have the necessary permissions and approvals before conducting any form of 
dynamic analysis.

