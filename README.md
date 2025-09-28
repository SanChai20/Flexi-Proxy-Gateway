<h1 align="center">FlexiProxy Gateway</h1>
<p align="center">
  <strong>基于LiteLLM代理服务的FlexiProxy后端</strong>
  <br/>
  <strong>A Custom Plugin of LiteLLM Proxy Server</strong>
</p>

<div align="center">

[![GitHub](https://img.shields.io/badge/FlexiProxy-0.7.0-blue?logo=github)](https://github.com/SanChai20/Flexi-Proxy)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)
[![LiteLLM](https://img.shields.io/badge/LiteLLM-Docs-orange?logo=litellm)](https://docs.litellm.ai/docs/simple_proxy)

</div>

<p align="center">
  <a href="#-中文">中文</a> •
  <a href="#-english">English</a>
</p>



## 中文

### 本地部署

#### **Windows 操作系统**

执行`admin/os/windows/launch.bat`文件，按照指示配置环境变量即可

#### **Linux 操作系统**

跳转至`admin/os/linux`目录下，执行`chmod u+x launch.sh`添加权限，然后执行`./launch.sh`并按照指示配置环境变量即可

> 通过Windows上的VS Code部署至服务器时，如果手动拷贝，可能会遇到`launch.sh`无法执行的问题，这是因为Windows风格换行符的问题，需要先执行`dos2unix launch.sh`转成Unix格式

## English

### Local Deployment

#### **Windows OS**

Run the `admin/os/windows/launch.bat` file and follow the prompts to configure the environment variables.

#### **Linux OS**

Navigate to the `admin/os/linux` directory, run `chmod u+x launch.sh` to add execute permission, then run `./launch.sh` and follow the prompts to configure the environment variables.

> When deploying to the server from VS Code on Windows, if you copy the file manually, you may encounter an issue where `launch.sh` cannot be executed. This happens because of Windows-style line endings. You need to run `dos2unix launch.sh` first to convert it to Unix format.