---
template: overrides/main.html
title: Job&CronJob
---

# Job&CronJob

接下来给大家介绍另外一类资源对象：`Job`，{++我们在日常的工作中经常都会遇到一些需要进行批量数据处理和分析的需求，当然也会有按时间来进行调度的工作，在我们的 Kubernetes 集群中为我们提供了 Job 和 CronJob 两种资源对象来应对我们的这种需求++}。

``#!css Job`` 负责处理任务，即仅执行一次的任务，它保证批处理任务的一个或多个 Pod 成功结束。而``#!css CronJob`` 则就是在 Job 上加上了时间调度。

## Job

我们用 `Job` 这个资源对象来创建一个任务，我们定义一个 `Job` 来执行一个倒计时的任务，对应的资源清单如下所示：

``` yaml hl_lines="9"
# job-demo.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: job-demo
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: counter
        image: busybox
        command:
        - "bin/sh"
        - "-c"
        - "for i in 9 8 7 6 5 4 3 2 1; do echo $i; done"
```

我们可以看到 `Job` 中也是一个 Pod 模板，和之前的 Deployment、StatefulSet 之类的是一致的，只是 Pod 中的容器要求是一个任务，而不是一个常驻前台的进程了，因为需要退出。另外值得注意的是 `Job` 的 ``#!css RestartPolicy`` 仅支持 ``#!yaml Never`` 和 ``#!yaml OnFailure`` 两种，不支持 ``#!yaml Always``。我们知道 `Job` 就相当于来执行一个批处理任务，执行完就结束了，如果支持 ``#!yaml Always`` 的话是不是就陷入了死循环了？

直接创建这个 Job 对象：

``` bash
➜  ~ kubectl apply -f job-demo.yaml
job.batch/job-demo created
➜  ~  kubectl get job
NAME       COMPLETIONS   DURATION   AGE
job-demo   1/1           19s        42s
➜  ~ kubectl get pods
NAME                READY   STATUS      RESTARTS   AGE
job-demo--1-p9s5r   0/1     Completed   0          52s
```

`Job` 对象创建成功后，我们可以查看下对象的详细描述信息：

``` bash
➜  ~ kubectl describe job job-demo
Name:             job-demo
Namespace:        default
Selector:         controller-uid=10618fc6-5610-41c6-bdeb-531167716179
Labels:           controller-uid=10618fc6-5610-41c6-bdeb-531167716179
                  job-name=job-demo
Annotations:      <none>
Parallelism:      1
Completions:      1
Completion Mode:  NonIndexed
Start Time:       Sat, 13 Nov 2021 18:34:17 +0800
Completed At:     Sat, 13 Nov 2021 18:34:36 +0800
Duration:         19s
Pods Statuses:    0 Running / 1 Succeeded / 0 Failed
Pod Template:
  Labels:  controller-uid=10618fc6-5610-41c6-bdeb-531167716179
           job-name=job-demo
  Containers:
   counter:
    Image:      busybox
    Port:       <none>
    Host Port:  <none>
    Command:
      bin/sh
      -c
      for i in 9 8 7 6 5 4 3 2 1; do echo $i; done
    Environment:  <none>
    Mounts:       <none>
  Volumes:        <none>
Events:
  Type    Reason            Age   From            Message
  ----    ------            ----  ----            -------
  Normal  SuccessfulCreate  73s   job-controller  Created pod: job-demo--1-p9s5r
  Normal  Completed         54s   job-controller  Job completed
```

可以看到，Job 对象在创建后，它的 Pod 模板，被自动加上了一个 ``#!css controller-uid=< 一个随机字符串 > ``这样的 Label 标签，而这个 Job 对象本身，则被自动加上了这个 Label 对应的 Selector，从而 保证了 Job 与它所管理的 Pod 之间的匹配关系。而 Job 控制器之所以要使用这种携带了 UID 的 Label，就是为了避免不同 Job 对象所管理的 Pod 发生重合。

我们可以看到很快 Pod 变成了 `Completed` 状态，这是因为容器的任务执行完成正常退出了，我们可以查看对应的日志：

``` bash
➜  ~ kubectl logs job-demo--1-p9s5r
9
8
7
6
5
4
3
2
1
➜  ~ kubectl get pod
NAME                       READY   STATUS       RESTARTS   AGE
job-demo--1-p9s5r          0/1     Completed    0          11m
```

上面我们这里的 Job 任务对应的 Pod 在运行结束后，会变成 `Completed` 状态，但是如果执行任务的 Pod 因为某种原因一直没有结束怎么办呢？同样我们可以在 Job 对象中通过设置字段 ``#!css spec.activeDeadlineSeconds`` 来限制任务运行的最长时间，比如：

``` yaml
spec:
 activeDeadlineSeconds: 100
```

那么当我们的任务 Pod 运行超过了 100s 后，这个 Job 的所有 Pod 都会被终止，并且， Pod 的终止原因会变成 ``#!css DeadlineExceeded``。

如果的任务执行失败了，会怎么处理呢，这个和定义的 ``#!css restartPolicy`` 有关系，比如定义如下所示的 Job 任务，定义 `restartPolicy: Never` 的重启策略：

``` yaml
# job-failed-demo.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: job-failed-demo
spec:
  template:
    spec:
      containers:
      - name: test-job
        image: busybox
        command: ["echo123", "test failed job!"]
      restartPolicy: Never
```

直接创建上面的资源对象：

``` bash
➜  ~ kubectl apply -f job-failed-demo.yaml
job.batch/job-failed-demo created
➜  ~ kubectl get pod
NAME                       READY   STATUS       RESTARTS   AGE
job-failed-demo--1-87wvj   0/1     StartError   0          4m40s
job-failed-demo--1-bl7jm   0/1     StartError   0          5m7s
job-failed-demo--1-dcmph   0/1     StartError   0          3m
job-failed-demo--1-hb24j   0/1     StartError   0          20s
job-failed-demo--1-n7h24   0/1     StartError   0          4m20s
job-failed-demo--1-q7vxq   0/1     StartError   0          5m24s
```

可以看到当我们设置成 `Never` 重启策略的时候，Job 任务执行失败后会不断创建新的 Pod，但是不会一直创建下去，会根据 ``#!css spec.backoffLimit`` 参数进行限制，默认为<span class="jade">6</span>，通过该字段可以定义重建 Pod 的次数，另外需要注意的是 Job 控制器重新创建 Pod 的间隔是呈指数增加的，即下一次重新创建 Pod 的动作会分别发生在 `10s、20s、40s…` 后。

但是如果我们设置的 ``#!css restartPolicy: OnFailure`` 重启策略，则当 Job 任务执行失败后不会创建新的 Pod 出来，只会不断重启 Pod。

除此之外，我们还可以通过设置 ``#!css spec.parallelism`` 参数来进行并行控制，该参数定义了一个 Job 在任意时间最多可以有多少个 Pod 同时运行。``#!css spec.completions`` 参数可以定义 Job 至少要完成的 Pod 数目。如下所示创建一个新的 Job 任务，设置允许并行数为2，至少要完成的 Pod 数为8：

``` yaml
# job-para-demo.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: job-para-test
spec:
  parallelism: 2
  completions: 8
  template:
    spec:
      containers:
      - name: test-job
        image: busybox
        command: ["echo", "test paralle job!"]
      restartPolicy: Never
```

``` bash
➜  ~ kubectl get pod
NAME                     READY   STATUS              RESTARTS   AGE
job-para-test--1-rwxm8   0/1     ContainerCreating   0          6s
job-para-test--1-vgtxf   0/1     ContainerCreating   0          2s
➜  ~ kubectl get job
NAME            COMPLETIONS   DURATION   AGE
job-para-test   0/8           29s        29s
➜  ~ kubectl get job
NAME            COMPLETIONS   DURATION   AGE
job-para-test   8/8           111s       2m34s
➜  ~ kubectl get pod
NAME                     READY   STATUS      RESTARTS   AGE
job-para-test--1-7nk2x   0/1     Completed   0          76s
job-para-test--1-dcdvp   0/1     Completed   0          2m2s
job-para-test--1-k9sgw   0/1     Completed   0          2m36s
job-para-test--1-rwkkb   0/1     Completed   0          2m17s
job-para-test--1-rwxm8   0/1     Completed   0          2m36s
job-para-test--1-tqlzd   0/1     Completed   0          106s
job-para-test--1-vgtxf   0/1     Completed   0          2m32s
job-para-test--1-vxj6b   0/1     Completed   0          91s
```

可以看到一次可以有2个 Pod 同时运行，需要8个 Pod 执行成功，如果不是8个成功，那么会根据 ``#!css restartPolicy`` 的策略进行处理，可以认为是一种检查机制。

## CronJob

``#!css CronJob`` 其实就是在 `Job` 的基础上加上了时间调度，我们可以在给定的时间点运行一个任务，也可以周期性地在给定时间点运行。这个实际上和我们 Linux 中的 `crontab` 就非常类似了。

一个 `CronJob` 对象其实就对应中 `crontab` 文件中的一行，它根据配置的时间格式周期性地运行一个 `Job`，格式和 `crontab` 也是一样的。

crontab 的格式为：分 时 日 月 星期 要运行的命令 。

- 第1列分钟 0～59
- 第2列小时 0～23
- 第3列日 1～31
- 第4列月 1～12
- 第5列星期 0～7（0和7表示星期天）
- 第6列要运行的命令

现在，我们用 `CronJob` 来管理我们上面的 `Job` 任务，定义如下所示的资源清单：
``` yaml
# cronjob-demo.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cronjob-demo
spec:
  schedule: "*/1 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
          - name: hello
            image: busybox
            args:
            - "bin/sh"
            - "-c"
            - "for i in 9 8 7 6 5 4 3 2 1; do echo $i; done"
```

这里的 Kind 变成了 `CronJob` 了，要注意的是 ``#!css .spec.schedule``字段是必须填写的，用来指定任务运行的周期，格式就和 `crontab` 一样，另外一个字段是 ``#!css .spec.jobTemplate``, 用来指定需要运行的任务，格式当然和 `Job` 是一致的。还有一些值得我们关注的字段 ``#!css .spec.successfulJobsHistoryLimit``(默认为<span class="jade">3</span>) 和 ``#!css .spec.failedJobsHistoryLimit``(默认为<span class="jade">1</span>)，表示历史限制，是可选的字段，指定可以保留多少完成和失败的 `Job`。然而，当运行一个 `CronJob` 时，`Job` 可以很快就堆积很多，所以一般推荐设置这两个字段的值，如果设置限制的值为 0，那么相关类型的 `Job` 完成后将不会被保留。

我们直接新建上面的资源对象：

``` bash
➜  ~ kubectl apply -f cronjob-demo.yaml
cronjob "cronjob-demo" created
```

然后可以查看对应的 Cronjob 资源对象：

``` bash
➜  ~ kubectl get cronjob
NAME           SCHEDULE      SUSPEND   ACTIVE   LAST SCHEDULE   AGE
cronjob-demo   */1 * * * *   False     0        28s             36s
```

稍微等一会儿查看可以发现多了几个 Job 资源对象，这个就是因为上面我们设置的 CronJob 资源对象，每1分钟执行一个新的 Job：

``` bash
➜  ~ kubectl get job
NAME                    COMPLETIONS   DURATION   AGE
cronjob-demo-27280016   1/1           17s        118s
cronjob-demo-27280017   1/1           16s        58s
➜  ~ kubectl get pods
NAME                             READY   STATUS              RESTARTS   AGE
cronjob-demo-27280016--1-kvkt4   0/1     Completed           0          2m9s
cronjob-demo-27280017--1-pkwdb   0/1     Completed           0          69s
cronjob-demo-27280018--1-q9n7w   0/1     ContainerCreating   0          9s
```

这个就是 CronJob 的基本用法，一旦不再需要 CronJob，我们可以使用 kubectl 命令删除它：

``` bash
➜  ~ kubectl delete cronjob cronjob-demo
cronjob "cronjob-demo" deleted
```

不过需要注意的是这将会终止正在创建的 Job，但是运行中的 Job 将不会被终止，不会删除 Job 或 它们的 Pod。

思考：那如果我们想要在每个节点上去执行一个 Job 或者 Cronjob 又该怎么来实现呢？
