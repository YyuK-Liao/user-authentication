# simple-file-based-multi-user-authentication

---

此程式主要展示基於認證文件的多用戶認證流程，靈感是源自於Linux的使用者認證。（用於資安研究）



## Features

---

+ ### Create New User after Checking

  ![image](https://github.com/yuuR-Meow/simple-file-base-muti-user-authentication/blob/main/sample_image/1.createUser.gif)

+ ### Deny Toleration （3 times per application exercution）

  ![image](https://github.com/yuuR-Meow/simple-file-base-muti-user-authentication/blob/main/sample_image/2.deny.gif)

+ ### Time for Password Expiration（３minutes default）

  ![image](https://github.com/yuuR-Meow/simple-file-base-muti-user-authentication/blob/main/sample_image/3.login.gif)

+ ### Repeat-Login and Warning

  ![image](https://github.com/yuuR-Meow/simple-file-base-muti-user-authentication/blob/main/sample_image/4.relogin.gif)

+ ### Input Password Without Display

  ![image](https://github.com/yuuR-Meow/simple-file-base-muti-user-authentication/blob/main/sample_image/5.hiddenPW.png)



## About User Data?

---

+ **Field In File	"user_auth.dat"**：

  > username：password：lastChange：expired：lastLogin：connection

  ​	*	Actually, symbol '：' is halfwidth in file.

  ​	*	Store time type is Unixnano.

+ **Password Hash**：

  SHA3-512 as hash algorithm, and encode to hexadecimal text.

+ **Password Limits**

  1. length over 8
  2. include Lower and Upper Case

  

## Main Test Platform

---

+ Microsoft Terminal（Windows）
+ Bash （Ubuntu）

## Author

---

yuuR-Meow	a.k.a.	JunWei Liao

## License

---

Baic MIT licence. 
