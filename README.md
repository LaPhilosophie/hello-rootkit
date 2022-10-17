# hello-rootkit

要求
> 编写一个kernel rootkit，包括进程隐藏、文件隐藏、端口隐藏、驱动隐藏、进程保护等功能，可以自行选择window或linux系统

# 进度

- [√] 模块隐藏
- [√] 提权
- [√] 文件隐藏
- [√]进程隐藏
- [ ] 端口隐藏
# 开发规范

- **为了项目维护和后续制作展示PPT，请务必在代码中加入注释**
- 由于项目较小，暂时只使用一个主开发分支 `main`，将代码直接提交到`main`分支
- 每次使用`git push`将本地代码推送到远程之前，先运行`git pull`或者`git fetch`命令处理冲突
- `git commit` 要对推送的内容有所说明
- 参与开发的同学将会被加入仓库的`collaborators`，获得仓库的访问权限。关于在github上进行多人合作的[参考](https://blog.csdn.net/sculpta/article/details/104448310)

# 开发说明

## 贡献
经本地测试后push到仓库的main分支
## 开发环境
rootkit与内核版本是强相关的，只可以在固定的内核上运行。内核版本号可以通过`uname -r`查看，如果内核版本号低，可以使用[apt的包进行升级](https://askubuntu.com/questions/187502/how-do-i-use-apt-get-to-update-to-the-latest-kernel)，如果过高可以自行搜索kernel downgrade的方法

- 内核版本：5.4.0-126-generic
- 开发工具：建议 vscode + ssh remote 到虚拟机，并使用虚拟机快照，当rootkit将环境搞崩之后可以快速恢复

## 运行rootkit
- `git clone`仓库到本地
- cd到项目根目录，运行make，生成目标文件
- 执行`make install`安装模块

具体细节参见项目Makefile的编写

# 技术文档


# 参考资料

- [(nearly) Complete Linux Loadable Kernel Modules](http://www.ouah.org/LKM_HACKING.html)
- [awesome-linux-rootkits](https://github.com/milabs/awesome-linux-rootkits)
- [简易 Linux Rootkit 编写入门指北](https://arttnba3.cn/2021/07/07/CODE-0X01-ROOTKIT/)
- [Reptile](https://github.com/f0rb1dd3n/Reptile)
- [Sample Rootkit for Linux](https://github.com/ivyl/rootkit)
- [【Rootkit 系列研究】Rootkit 检测技术发展现状](https://paper.seebug.org/1871/)
- https://github.com/plusls/rootkit
- https://github.com/TangentHuang/ucas-rootkit
- https://xcellerator.github.io/posts/linux_rootkits_07/
- https://github.com/torvalds/linux/tree/325d0eab4f31c6240b59d5b2b8042c88f59405b5/fs
- https://docs-conquer-the-universe.readthedocs.io/zh_CN/latest/linux_rootkit/fundamentals.html
- https://github.com/vkobel/linux-syscall-hook-rootkit
- https://linux.die.net/man/2/getdents64