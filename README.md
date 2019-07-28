# Memhack

Memhack is a memory hacker that modify the process's memory
according to PID provided. 
Maybe you can use it to modify your game's data.

## Usage
Before running, use `make` to build `memhack` first.
Then, use `./memhack [PID]` to hack the process with the pid of [PID].

Memhack has a console when running. 
The commands that memhack enables are shown as bellow.

* `pause`: Pause the process you want to hack.
* `resume`: Resume the process to run again.
* `lookup <number>`: It will lookup memories that have the value of `<number>` and list them for you, which are called candidate memories.
* `setup <number>`: If there only left one candidate memory, it will set it to the `<number>` you give.
* `exit`: Exit `memhack`.

So, the basic usage of `memhack` is: 

    pause the process
    lookup the value of the memory you want to modify
    while there are more than one candidate memories
        resume process
        do some changes in your process, e.g. play your game for a while
        pause the process
        lookup the updated value of the memory you want to modify
    setup new number to the only candidate memory
