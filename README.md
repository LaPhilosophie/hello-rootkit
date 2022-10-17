# hello-rootkit
**内核环境：5.10**

要求
> 编写一个kernel rootkit，包括进程隐藏、文件隐藏、端口隐藏、驱动隐藏、进程保护等功能，可以自行选择window或linux系统

# 进度

- [√] 模块隐藏
- [√] 提权
- [√] 进程隐藏
- [√] 文件隐藏
- [√] 端口隐藏


# 使用方法

**安装模块**

```
sudo insmod rootkit.ko
```

**卸载模块**

```
sudo rmmod rootkit.ko
```

**模块隐藏与恢复**

```
echo hidemodule >/dev/null
echo showmodule >/dev/null
```

![image-20221017110124032](https://img-blog.csdnimg.cn/8b2e6b1f402d413391a3ff6e0f96ea73.png)

**模块提权**

```
读取/dev/null，即可实现程序提权
```

**进程隐藏与恢复**

```
echo hideprocess [PID] >/dev/null
echo showprocess [PID] >/dev/null
```

![image-20221017110313469](https://img-blog.csdnimg.cn/057cb11e20fd405f922d85cd4f85eca5.png)

**文件隐藏与回复**

```
echo hidefile [filename] >/dev/null
echo showfile [filename] >/dev/null
```

![image-20221017110405347](https://img-blog.csdnimg.cn/0ae5b7c4fb7a4e3dbae019d361c16977.png)

**端口隐藏与回复**

```
echo hideport [port] >/dev/null
echo showport [port] >/dev/null
```

![image-20221017110534932](https://img-blog.csdnimg.cn/741022a389064992a32171e9724b4395.png)
# 开发规范

- **为了项目维护和后续制作展示PPT，请务必在代码中加入注释**
- 由于项目较小，只使用一个分支 `main`，代码直接提交到`main`分支
- 每次使用`git push`将本地代码推送到远程之前，先`git pull`一下处理冲突
- `git commit` 规范：要对推送的内容有所说明
- 参与开发的同学将会被加入仓库的collaborators，获得仓库的访问权限 
# 参考资料

- [(nearly) Complete Linux Loadable Kernel Modules](http://www.ouah.org/LKM_HACKING.html)
- [awesome-linux-rootkits](https://github.com/milabs/awesome-linux-rootkits)
- [简易 Linux Rootkit 编写入门指北](https://arttnba3.cn/2021/07/07/CODE-0X01-ROOTKIT/)
- [Reptile](https://github.com/f0rb1dd3n/Reptile)
- [Sample Rootkit for Linux](https://github.com/ivyl/rootkit)
- [GitHub 多人队伍合作详细教程](https://blog.csdn.net/sculpta/article/details/104448310)
- [【Rootkit 系列研究】Rootkit 检测技术发展现状](https://paper.seebug.org/1871/)
- https://github.com/plusls/rootkit
- https://github.com/TangentHuang/ucas-rootkit