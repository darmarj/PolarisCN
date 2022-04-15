---
template: overrides/main.html
title: RBAC
---

# 权限控制 - RBAC

前面我们已经学习一些常用的资源对象的使用，我们知道对于资源对象的操作都是通过 APIServer 进行的，那么集群是怎样知道我们的请求就是合法的请求呢？这个就需要了解 Kubernetes 中另外一个非常重要的知识点了：`#!css RBAC`（基于角色的权限控制）。

管理员可以通过 Kubernetes API 动态配置策略来启用RBAC，需要在 kube-apiserver 中添加参数--authorization-mode=RBAC，如果使用的 kubeadm 安装的集群那么是默认开启了 RBAC 的，可以通过查看 Master 节点上 apiserver 的静态 Pod 定义文件：

```shell
➜  ~ cat /etc/kubernetes/manifests/kube-apiserver.yaml
...
    - --authorization-mode=Node,RBAC
...
```

如果是二进制的方式搭建的集群，添加这个参数过后，记得要重启 kube-apiserver 服务。

## API 对象

在学习 RBAC 之前，我们还需要再去理解下 Kubernetes 集群中的对象，我们知道，在 Kubernetes 集群中，Kubernetes 对象是我们持久化的实体，就是最终存入 etcd 中的数据，集群中通过这些实体来表示整个集群的状态。前面我们都直接编写的 YAML 文件，通过 kubectl 来提交的资源清单文件，然后创建的对应的资源对象，那么它究竟是如何将我们的 YAML 文件转换成集群中的一个 API 对象的呢？

这个就需要去了解下声明式 API的设计，Kubernetes API 是一个以 JSON 为主要序列化方式的 HTTP 服务，除此之外也支持 Protocol Buffers 序列化方式，主要用于集群内部组件间的通信。为了可扩展性，Kubernetes 在不同的 API 路径（比如/api/v1 或者 /apis/batch）下面支持了多个 API 版本，不同的 API 版本意味着不同级别的稳定性和支持：
