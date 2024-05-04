**Module 2: Disassembling Android Applications (4 hours)**

In this module, we will learn how to disassemble Android applications using tools such as JD-GUI and Android Studio's built-in decompilation feature. We will also explore some common techniques used in reverse engineering and debugging.

**Section 1: Introduction to Reverse Engineering**

Reverse engineering is the process of analyzing an existing application or program to understand its inner workings, including the source code, algorithms, and data structures. In the context of Android applications, reverse engineering can be used to:

* Analyze malware and other malicious code
* Identify security vulnerabilities and develop countermeasures
* Understand how an app works and optimize its performance
* Re-engineer or re-architect an app for reuse or modification

**Section 2: JD-GUI**

JD-GUI (Java Decompiler) is a popular tool used to disassemble Java-based Android applications. It can be used to:

* Deobfuscate obfuscated code
* Identify encryption and compression techniques
* Analyze the flow of an application's logic

Here are some steps to follow when using JD-GUI:

1. Download and install JD-GUI from the official website.
2. Create a new project in JD-GUI by clicking "File" > "New Project".
3. Add your Android APK file to the project by dragging it into the JD-GUI window or by clicking "File" > "Open File" and selecting the APK file.
4. JD-GUI will decompile the APK file and display the disassembled code in a tree-like structure.

**Example: Reversing a Simple Android App**

Let's take a simple Android app that displays a greeting message on the screen. We'll use JD-GUI to reverse engineer the app and analyze its code.

**Step 1:** Download and install JD-GUI from the official website.

**Step 2:** Create a new project in JD-GUI by clicking "File" > "New Project".

**Step 3:** Add your Android APK file (e.g. "HelloWorld.apk") to the project by dragging it into the JD-GUI window or by clicking "File" > "Open File" and selecting the APK file.

**Step 4:** JD-GUI will decompile the APK file and display the disassembled code in a tree-like structure.

Here's an example of what the disassembled code might look like:
```java
public class HelloWorldActivity extends AppCompatActivity {
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_hello_world);
        TextView tv = (TextView) findViewById(R.id.tv_message);
        tv.setText("Hello, World!");
    }
}
```
In this example, we can see the disassembled code for a simple Android activity that displays a greeting message on the screen. We can analyze the code to understand how it works and identify any potential security vulnerabilities.

**Hands-on Exercise: Reversing a Simple Android App**

1. Download the sample APK file ("HelloWorld.apk") from the course materials.
2. Open JD-GUI and create a new project by clicking "File" > "New Project".
3. Add the "HelloWorld.apk" file to the project by dragging it into the JD-GUI window or by clicking "File" > "Open File" and selecting the APK file.
4. Analyze the disassembled code in JD-GUI and identify any security vulnerabilities or potential issues.

**Section 3: Android Studio's Built-in Decompilation Feature**

Android Studio provides a built-in decompilation feature that can be used to reverse engineer Java-based Android applications. This feature is available under the "Refactor" menu item.

Here are some steps to follow when using Android Studio's decompilation feature:

1. Open your Android project in Android Studio.
2. Right-click on the APK file (e.g. "HelloWorld.apk") and select "Decompile..." from the context menu.
3. The decompiled code will be displayed in a new window.
4. You can analyze the code to understand how it works and identify any potential security vulnerabilities or issues.

**Example: Reversing a Simple Android App using Android Studio's Decompilation Feature**

Let's take the same simple Android app that displays a greeting message on the screen. We'll use Android Studio's decompilation feature to reverse engineer the app and analyze its code.

1. Open your Android project in Android Studio.
2. Right-click on the APK file (e.g. "HelloWorld.apk") and select "Decompile..." from the context menu.
3. The decompiled code will be displayed in a new window.

Here's an example of what the decompiled code might look like:
```java
public class HelloWorldActivity extends AppCompatActivity {
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_hello_world);
        TextView tv = (TextView) findViewById(R.id.tv_message);
        tv.setText("Hello, World!");
    }
}
```
In this example, we can see the decompiled code for a simple Android activity that displays a greeting message on the screen. We can analyze the code to understand how it works and identify any potential security vulnerabilities or issues.

**Hands-on Exercise: Reversing a Simple Android App using Android Studio's Decompilation Feature**

1. Open your Android project in Android Studio.
2. Right-click on the APK file (e.g. "HelloWorld.apk") and select "Decompile..." from the context menu.
3. Analyze the decompiled code to understand how it works and identify any potential security vulnerabilities or issues.

**Conclusion**

In this module, we learned how to disassemble Android applications using tools such as JD-GUI and Android Studio's built-in decompilation feature. We also explored some common techniques used in reverse engineering and debugging. By reversing a simple Android app, we can gain insights into its inner workings and identify potential security vulnerabilities or issues.

**Additional Resources**

* JD-GUI official website: https://java.decompiler.free.fr/
* Android Studio documentation: https://developer.android.com/studio/index.html
* Reverse engineering tutorials: https://www.owasp.org/index.php/Reverse_engineering

Note: The above module is just a sample and may not cover all the topics or provide hands-on exercises for every topic. It's meant to be a starting point for students who want to learn about disassembling Android applications.