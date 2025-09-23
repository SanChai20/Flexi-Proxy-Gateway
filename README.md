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





## 🇨🇳 中文

### 本地部署

#### **Windows 操作系统**

1. 创建Python虚拟环境

    ```cmd
    py -m venv .venv
    ```

2. 激活虚拟环境
   
   ```cmd
   .\.venv\Scripts\activate
   ```

3. 安装依赖库

    ```cmd
    pip install -r requirements.txt
    ```

4. 配置环境变量

    ```cmd
    cp .env.example .env
    ```

    如果部署生产环境，使用此指令:
    ```cmd
    set LITELLM_MODE=PRODUCTION
    ```

5. 生成密钥对

    ```cmd
    python admin/create_key_pair.py
    ```


6. 启动litellm代理服务

    ```cmd
    litellm --config config.yaml --port 4000 
    ```


#### **Linux 操作系统**

1. 创建Python虚拟环境

    ```cmd
    python3 -m venv .venv
    ```

2. 激活虚拟环境
   
   ```cmd
   source .venv/bin/activate
   ```

3. 安装依赖库

    ```cmd
    pip3 install -r requirements.txt
    ```

4. 配置环境变量

    ```cmd
    cp .env.example .env
    ```

    如果部署生产环境，使用此指令:
    ```cmd
    export LITELLM_MODE=PRODUCTION
    ```

5. 生成密钥对

    ```cmd
    python3 admin/create_key_pair.py
    ```


6. 启动litellm代理服务

    ```cmd
    litellm --config config.yaml --port 4000
    ```




## 🇺🇸 English

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
    pip install -r requirements.txt
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
    pip3 install -r requirements.txt
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