while true; do
    curl -s http://localhost:7627/snapraid/v1/disks
    curl -s http://localhost:7627/snapraid/v1/activity
    curl -s http://localhost:7627/snapraid/v1/tasks
    curl -s http://localhost:7627/snapraid/v1/config
    curl -s http://localhost:7627/snapraid/v1/array
    curl -s http://localhost:7627/snapraid/v1/state
done
