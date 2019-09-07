package main

type Router struct {
	Configuration *Configuration
	LANInterfaces []string
	LANQueues     []int
	WANInterfaces []string
	WANQueues     []int
}

func NewRouter(conf *Configuration, lanInterfaces []string, lanQueues []int, wanInterfaces []string, wanQueues []int) *Router {
	return &Router{
		Configuration: conf,
		LANInterfaces: lanInterfaces,
		WANInterfaces: wanInterfaces,
		LANQueues:     lanQueues,
		WANQueues:     wanQueues,
	}
}

func (r *Router) Run() {
	panic("unimplemented")
}
