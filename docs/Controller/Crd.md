---
template: overrides/main.html
title: Crd
---

# CRD

`#!css Custom Resource Define` 简称 CRD，是 Kubernetes（v1.7+）为提高可扩展性，让开发者去自定义资源的一种方式。CRD 资源可以动态注册到集群中，注册完毕后，用户可以通过 kubectl 来创建访问这个自定义的资源对象，类似于操作 Pod 一样。不过需要注意的是 CRD 仅仅是资源的定义而已，需要一个 Controller 去监听 CRD 的各种事件来添加自定义的业务逻辑。

## 定义

如果说只是对 CRD 资源本身进行 CRUD 操作的话，不需要 Controller 也是可以实现的，相当于就是只有数据存入了 etcd 中，而没有对这个数据的相关操作而已。比如我们可以定义一个如下所示的 CRD 资源清单文件：

``` yaml
# crd-demo.yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  # name 必须匹配下面的spec字段：<plural>.<group>
  name: crontabs.stable.example.com
spec:
  # group 名用于 REST API 中的定义：/apis/<group>/<version>
  group: stable.example.com
  # 列出自定义资源的所有 API 版本
  versions:
  - name: v1beta1  # 版本名称，比如 v1、v2beta1 等等
    served: true  # 是否开启通过 REST APIs 访问 `/apis/<group>/<version>/...`
    storage: true # 必须将一个且只有一个版本标记为存储版本
    schema:  # 定义自定义对象的声明规范
      openAPIV3Schema:
        description: Define CronTab YAML Spec
        type: object
        properties:
          spec:
            type: object
            properties:
              cronSpec:
                type: string
              image:
                type: string
              replicas:
                type: integer
  # 定义作用范围：Namespaced（命名空间级别）或者 Cluster（整个集群）
  scope: Namespaced
  names:
    # kind 是 sigular 的一个驼峰形式定义，在资源清单中会使用
    kind: CronTab
    # plural 名字用于 REST API 中的定义：/apis/<group>/<version>/<plural>
    plural: crontabs
    # singular 名称用于 CLI 操作或显示的一个别名
    singular: crontab
    # shortNames 相当于缩写形式
    shortNames:
    - ct
```

!!! WARNING
	需要注意的是 v1.16 版本以后已经 GA 了，使用的是 v1 版本，之前都是 v1beta1，定义规范有部分变化，所以要注意版本变化。

这个地方的定义和我们定义普通的资源对象比较类似，我们说我们可以随意定义一个自定义的资源对象，但是在创建资源的时候，肯定不是任由我们随意去编写 YAML 文件的，当我们把上面的 CRD 文件提交给 Kubernetes 之后，Kubernetes 会对我们提交的声明文件进行校验，从定义可以看出 CRD 是基于 [OpenAPI v3 schem](https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.0.md#schemaObject) 进行规范的。**这种校验只是对于字段的类型进行校验，比较初级**，<span class="jade">如果想要更加复杂的校验，这个时候就需要通过 Kubernetes 的 admission webhook 来实现了</span>。关于校验的更多用法，可以前往[官方文档](https://kubernetes.io/docs/tasks/access-kubernetes-api/custom-resources/custom-resource-definitions/#validation)查看。

同样现在我们可以直接使用 kubectl 来创建这个 CRD 资源清单：

``` bash
➜  ~ kubectl apply -f crd-demo.yaml
customresourcedefinition.apiextensions.k8s.io/crontabs.stable.example.com created
```

这个时候我们可以查看到集群中已经有我们定义的这个 CRD 资源对象了：

``` bash
➜  ~ kubectl get crd |grep example
crontabs.stable.example.com                      2019-12-19T02:37:54Z
```

这个时候一个新的 namespace 级别的 RESTful API 就会被创建：

``` bash
/apis/stable/example.com/v1beta1/namespaces/*/crontabs/...
```

然后我们就可以使用这个 API 端点来创建和管理自定义的对象，这些对象的类型就是上面创建的 CRD 对象规范中的 `CronTab`。

现在在 Kubernetes 集群中我们就多了一种新的资源叫做 `#!yaml crontabs.stable.example.com`，我们就可以使用它来定义一个 `CronTab` 资源对象了，这个自定义资源对象里面可以包含的字段我们在定义的时候通过 `schema` 进行了规范，比如现在我们来创建一个如下所示的资源清单：

``` yaml
# crd-crontab-demo.yaml
apiVersion: stable.example.com/v1beta1
kind: CronTab
metadata:
  name: my-new-cron-object
spec:
  cronSpec: "* * * * */5"
  image: my-awesome-cron-image
```

我们可以直接创建这个对象：
``` bash
➜  ~ kubectl apply -f crd-crontab-demo.yaml
crontab.stable.example.com/my-new-cron-object created
```

然后我们就可以用 kubectl 来管理我们这里创建 CronTab 对象了，比如：

``` bash
➜  ~ kubectl get ct  # 简写
NAME                 AGE
my-new-cron-object   42s
➜  ~ kubectl get crontab
NAME                 AGE
my-new-cron-object   88s
```

{++在使用 kubectl 的时候，资源名称是不区分大小写的，我们可以使用 CRD 中定义的单数或者复数形式以及任何简写++}。我们也可以查看创建的这个对象的原始 YAML 数据：

``` bash hl_lines="18 19"
➜  ~ kubectl get ct -o yaml
apiVersion: v1
items:
- apiVersion: stable.example.com/v1beta1
  kind: CronTab
  metadata:
    annotations:
      kubectl.kubernetes.io/last-applied-configuration: |
        {"apiVersion":"stable.example.com/v1beta1","kind":"CronTab","metadata":{"annotations":{},"name":"my-new-cron-object","namespace":"default"},"spec":{"cronSpec":"* * * * */5","image":"my-awesome-cron-image"}}
    creationTimestamp: "2019-12-19T02:52:55Z"
    generation: 1
    name: my-new-cron-object
    namespace: default
    resourceVersion: "12342275"
    selfLink: /apis/stable.example.com/v1beta1/namespaces/default/crontabs/my-new-cron-object
    uid: dace308d-5f54-4232-9c7b-841adf6bab62
  spec:
    cronSpec: '* * * * */5'
    image: my-awesome-cron-image
kind: List
metadata:
  resourceVersion: ""
  selfLink: ""
```

我们可以看到它包含了上面我们定义的 `cronSpec` 和 `image` 字段。

## Controller

就如上面我们说的，现在我们自定义的资源创建完成了，但是也只是单纯的把资源清单数据存放到了 etcd 中而已，并没有什么其他用处，因为我们没有定义一个对应的 Controller 来处理他。

官方提供了一个自定义 `Controller` 的[示例](https://github.com/kubernetes/sample-controller)：

- 如何注册资源 Foo
- 如何创建、删除和查询 Foo 对象
- 如何监听 Foo 资源对象的变化情况

要想了解 Controller 的实现原理和方式，我们就需要了解下 client-go 这个库的实现，Kubernetes 部分代码也是基于这个库实现的，也包含了开发自定义控制器时可以使用的各种机制，这些机制在 `#!css client-go` 源码的 [css tools/cache](https://github.com/kubernetes/client-go/tree/master/tools/cache) 目录下面有定义。

下图显示了 client-go 中的各个组件是如何工作的以及与我们要编写的自定义控制器代码的交互入口：

[![client-go-controller-interaction](../assets/images/client-go-controller-interaction.jpeg "client-go-controller-interaction")](../assets/images/client-go-controller-interaction.jpeg "client-go-controller-interaction")

<span class="jade">client-go 组件</span>：

- **Reflector**：通过 Kubernetes API 监控 Kubernetes 的资源类型 采用 `#!css List/Watch` 机制, 可以 Watch 任何资源包括 CRD 添加 object 对象到 FIFO 队列，然后 `Informer` 会从队列里面取数据
- **Informer**：controller 机制的基础，`#!css 循环处理` 从 Reflector 取出数据的object 对象，然后将数据给到 Indexer 去`#!css 缓存`，提供对象事件的 `#!css handler` 接口，只要给 Informer 添加 `#!css ResourceEventHandler` 实例的回调函数，去实现 <span class="rouge">`OnAdd(obj interface{})`、`OnUpdate(oldObj, newObj interface{})` 和 `OnDelete(obj interface{})`</span>，就可以处理好资源的创建、更新和删除操作了。 这三个方法
- **Indexer**：提供 object 对象的索引，是线程安全的，缓存对象的信息

<span class="jade">controller 组件</span>：

- **Informer reference**: `controller` 需要创建合适的 Informer 才能通过 `#!css Informer reference` 操作资源对象
- **Indexer reference**: `controller` 创建 `#!css Indexer reference` 然后去利用索引做相关处理
- **Resource Event Handlers**：Informer 会回调这些 `#!css handlers`
- **Work queue**: `Resource Event Handlers` 被回调后将 key 写到工作队列，这里的 key 相当于事件通知，后面根据取出事件后，做后续的处理
- **Process Item**：从工作队列中取出 key 后进行后续处理，具体处理可以通过 `Indexer reference controller` 可以直接创建上述两个引用对象去处理，也可以采用工厂模式，官方都有相关示例

`client-go/tool/cache/` 和自定义 `Controller` 的[控制流](https://itnext.io/how-to-create-a-kubernetes-custom-controller-using-client-go-f36a7a7536cc)：

[![client-go-controller-workflow](../assets/images/client-go-controller-workflow.png "client-go-controller-workflow")](../assets/images/client-go-controller-workflow.png "client-go-controller-workflow")

如上图所示主要有 **两个部分**，一个是发生在 `SharedIndexInformer` 中，另外一个是在自定义控制器中。

- [x] **Reflector** 通过 Kubernetes APIServer 执行对象（比如 Pod）的 `#!css ListAndWatch` 查询，记录和对象相关的三种事件类型`#!css Added、Updated、Deleted`，然后将它们传递到 `#!css DeltaFIFO` 中去。

- [x] **DeltaFIFO** 接收到事件和 watch 事件对应的对象，然后将他们转换为 `#!css Delta 对象`，这些 Delta 对象被附加到队列中去等待处理，对于已经删除的，会检查线程安全的 store 中是否已经存在该文件，从而可以避免在不存在某些内容时排队执行删除操作。

- [x] **Cache 控制器**（不要和自定义控制器混淆）调用 <span class="rouge">`#!css Pop()`</span> 方法从 DeltaFIFO 队列中出队列，Delta 对象将传递到 `#!css SharedIndexInformer` 的 <span class="rouge">`#!css HandleDelta()`</span> 方法中以进行进一步处理。

- [x] 根据 **Delta 对象的操作（事件）类型** ，首先在 <span class="rouge">`#!css HandleDeltas`</span> 方法中通过 indexer 的方法将对象保存到线程安全的 Store 中，然后通过 `#!css SharedIndexInformer` 下面 `#!yaml sharedProcessor` 的 <span class="rouge">`#!css distribution()`</span> 方法将这些对象发送到事件 handlers，这些事件处理器由自定义控制器通过 <span class="rouge">`#!css SharedInformer`</span> 的方法比如 `AddEventHandlerWithResyncPeriod()` 进行注册。
 
- [x] **已注册的事件处理器** 通过添加或更新时间的 <span class="rouge">`#!css MetaNamespaceKeyFunc()`</span> 或删除事件的 <span class="rouge">`#!css DeletionHandingMetaNamespaceKeyFunc()`</span> 将对象转换为格式为 namespace/name 或只是 name 的 key，然后将这个 key 添加到自定义控制器的 `#!css workqueue` 中，workqueues 的实现可以在 util/workqueue 中找到。

- [x] **自定义的控制器** 通过调用定义的 handlers 处理器从 `#!css workqueue` 中 pop 一个 key 出来进行处理，handlers 将调用 indexer 的 <span class="rouge">`#!css GetByKey()`</span> 从线程安全的 store 中获取对象，我们的业务逻辑就是在这个 handlers 里面实现


`client-go` 中也有自定义 Controller 的样例代码，位于：{++k8s.io/client-go/examples/workqueue/main.go++}。

## Operator

`Operator` 就可以看成是 CRD 和 Controller 的{++一种组合特例++}，Operator 是一种思想，它结合了特定领域知识并通过 CRD 机制扩展了 Kubernetes API 资源，使用户管理 Kubernetes 的内置资源（Pod、Deployment等）一样创建、配置和管理应用程序，{++Operator 是一个特定应用程序的控制器，通过扩展 Kubernetes API 资源以代表 Kubernetes 用户创建、配置和管理复杂应用程序的实例++}。通常包含资源模型定义和控制器，通过 Operator 通常是为了实现<span class="jade">某种特定软件（通常是有状态服务）的自动化运维</span>。

我们完全可以通过上面的方式编写一个 CRD 对象，然后去手动实现一个对应的 Controller 就可以实现一个 Operator，但是我们也发现从头开始去构建一个 CRD 控制器并不容易，需要对 Kubernetes 的 API 有深入了解，并且 RBAC 集成、镜像构建、持续集成和部署等都需要很大工作量。为了解决这个问题，社区就推出了对应的简单易用的 Operator 框架，**比较主流的是 [kubebuilder](https://github.com/kubernetes-sigs/kubebuilder) 和 [Operator Framework](https://coreos.com/operators)**，这两个框架的使用基本上差别不大，我们可以根据自己习惯选择一个即可。

## 参考文档

- [How to Create a Kubernetes Custom Controller Using client-go](https://itnext.io/how-to-create-a-kubernetes-custom-controller-using-client-go-f36a7a7536cc)
- [A deep dive into Kubernetes controllers](https://engineering.bitnami.com/articles/a-deep-dive-into-kubernetes-controllers.html)
