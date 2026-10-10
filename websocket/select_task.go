// Copyright 2023-2024 antlabs. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package websocket

import (
	"context"
	"sync"

	"github.com/antlabs/task/task/driver"
	// 空导入: 各个任务驱动的 init() 会把自己注册到 driver 的注册表里。
	// 少了它 GetAllRegister() 是空的, newTask 找不到 "onebyone"/"elastic"
	// 这些名字, 直接 panic(fio: no task driver found)。
	_ "github.com/antlabs/task/task"
)

type selectTask struct {
	taskDriverName string
	task           driver.Tasker
}
type selectTasks []selectTask

// 默认的业务协程池。以前是"每个 event loop 一个"(绑定到它自己的
// localTask), 现在事件循环归 engine, websocket 这层只在用户显式
// 选了非 io 模式时用到——一份进程级的就够。
//
// 惰性建: 默认 io 模式根本走不到这儿, 不该为一个没用到的模式起协程池。
var (
	defaultTasks     selectTasks
	defaultTasksOnce sync.Once
)

// 业务协程池的默认参数。原来是每个 event loop 一份配置，现在进程一份，
// 数值沿用迁移前的（8 起步、50 保底、3 万上限）——非 io 模式不是热路径，
// 没跟着重新调。
const (
	defTaskMin       = 50
	defTaskMax       = 30000
	defTaskInitCount = 8
)

// newTaskExecutor 按任务驱动名(elastic/onebyone/...)取一个 executor。
//
// 以前是 c.parent.localTask.newTask(taskName); event loop 搬去 engine 之后
// 没有 localTask 了, 改成进程级的一份。
func newTaskExecutor(taskName string) driver.TaskExecutor {
	defaultTasksOnce.Do(func() {
		var c driver.Conf
		defaultTasks = newSelectTask(context.Background(), defTaskInitCount, defTaskMin, defTaskMax, &c)
	})
	return defaultTasks.newTask(taskName)
}

// newTaskMu 串行化 newTask。
//
// driver 的 NewExecutor 会动 driver 对象自己的计数(见 antlabs/task 里
// io/elastic 的 NewExecutor), 而 newConn 是每个连接一个 go 程在跑,
// 并发进去就是数据竞争。这里排一下队: 建连路径每连接只走一次, 代价
// 可以忽略。
var newTaskMu sync.Mutex

func newSelectTask(ctx context.Context, initCount, min, max int, c *driver.Conf) []selectTask {

	all := driver.GetAllRegister()
	rv := make([]selectTask, 0, len(all))
	for _, val := range all {
		task := val.Driver.New(ctx, initCount, min, max, c)
		rv = append(rv, selectTask{
			taskDriverName: val.Name,
			task:           task,
		})
	}
	return rv
}

func (s *selectTasks) newTask(taskName string) driver.TaskExecutor {
	newTaskMu.Lock()
	defer newTaskMu.Unlock()

	for _, val := range *s {
		if val.taskDriverName == taskName {
			return val.task.NewExecutor()
		}
	}

	panic("fio: no task driver found:" + taskName)
}

func (s *selectTasks) GetGoroutines() int {
	total := 0
	for _, val := range *s {
		total += val.task.GetGoroutines()
	}

	return total
}
