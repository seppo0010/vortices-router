package main

type Router struct {
    Configuration *Configuration 
}

func NewRouter(conf *Configuration) *Router {
    return &Router{Configuration: conf}
}

func (r *Router) Run() {
    panic("unimplemented")
}
