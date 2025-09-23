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

1. 环境准备
    ```cmd
    // 创建Python虚拟环境
    py -m venv .venv    

    // 激活虚拟环境
    .\.venv\Scripts\activate 

    // 安装依赖库
    pip install -r requirements-windows.txt

    // 配置环境变量 (配置详情请见.env.example)
    cp .env.example .env
    set LITELLM_MODE=PRODUCTION

    // 生成密钥对
    python admin/create_key_pair.py
    ```
2. 服务启动
    ```cmd
    // 启动litellm代理服务
    litellm --config config.yaml --port 4000
    ```

#### **Linux 操作系统**

1. 环境准备
    ```cmd
    // 创建Python虚拟环境
    python3 -m venv .venv

    // 激活虚拟环境
    source .venv/bin/activate

    // 安装依赖库
    pip3 install -r requirements-linux.txt

    // 配置环境变量 (配置详情请见.env.example)
    cp .env.example .env
    export LITELLM_MODE=PRODUCTION

    // 生成密钥对
    python3 admin/create_key_pair.py
    ```
2. 服务启动
    ```cmd
    // 启动litellm代理服务
    litellm --config config.yaml --port 4000
    ```


## English

### Local Deployment


#### **Windows OS**


1. Create Python Virtual Environment

    ```cmd
    py -m venv .venv
    ```

2. Activate Virtual Environment
   
   ```cmd
   .\.venv\Scripts\activate
   ```

3. Install Dependencies

    ```cmd
    pip install -r requirements-windows.txt
    ```

4. Configure Environment Variables

    ```cmd
    cp .env.example .env
    ```

    if deploy for production, use this:
    ```cmd
    set LITELLM_MODE=PRODUCTION
    ```

5. Generate Key Pair

    ```cmd
    python admin/create_key_pair.py
    ```

6. Start LiteLLM Proxy Server

    ```cmd
    litellm --config config.yaml --port 4000 
    ```



#### **Linux OS**


1. Create Python Virtual Environment

    ```cmd
    python3 -m venv .venv
    ```

2. Activate Virtual Environment
   
   ```cmd
   source .venv/bin/activate
   ```

3. Install Dependencies

    ```cmd
    pip3 install -r requirements-linux.txt
    ```

4. Configure Environment Variables

    ```cmd
    cp .env.example .env
    ```

    if deploy for production, use this:
    ```cmd
    export LITELLM_MODE=PRODUCTION
    ```

5. Generate Key Pair

    ```cmd
    python3 admin/create_key_pair.py
    ```

6. Start LiteLLM Proxy Server

    ```cmd
    litellm --config config.yaml --port 4000
    ```