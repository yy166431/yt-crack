# YTUnlock

运行时去授权 dylib，用于 YouTube(亚马逊/TrollStore 卡密版)。

## 原理

该重打包版在启动时用一个 `LoginViewController`（卡密登录界面）拦住真正的 YouTube，
验证通过后才调用 `onAuthorized` 回调切换到主界面。作者服务器现已限制卡密。

本 dylib 不去破解那个控制流平坦化的验证函数，而是在运行时直接：

1. hook `LoginViewController -viewDidLoad`，加载完成后取出 `_onAuthorized` block 并执行 → 等同验证通过；
2. 短路 `submitTapped`，不再向作者服务器发起卡密校验；
3. 作者若改了类名，按 `setOnAuthorized:` + `submitTapped` 特征自动兜底定位。

纯 ObjC runtime + `%ctor`，不依赖 CydiaSubstrate，适合 TrollStore/巨魔注入。

## 构建

推送到 GitHub 后，Actions 自动在 macOS runner 上用 theos 编译，
产物 `YTUnlock.dylib` 在 workflow 的 **Artifacts** 里下载。

也可手动触发：Actions → Build YTUnlock dylib → Run workflow。

## 使用

用 TrollStore / 巨魔 将 `YTUnlock.dylib` 注入进 YouTube.app，重新签名安装即可。
（该 App 要求 iOS 16+，请在对应系统版本设备上测试。）

日志前缀：`[YTUnlock]`，可用 Console/idevicesyslog 观察 hook 是否命中。
