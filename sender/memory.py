import subprocess
import resource

def get_max_memory_usage(command):
    process = subprocess.Popen(command, shell=True, 
                               preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_AS, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)))
    process.wait()
    max_memory_kb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return max_memory_kb / 1024 # Convert from KB to MB

if __name__ == "__main__":
    cpp_program = "./send"
    max_memory_used = get_max_memory_usage(cpp_program)
    print("Max memory used by the C++ program:", max_memory_used, "MB")
