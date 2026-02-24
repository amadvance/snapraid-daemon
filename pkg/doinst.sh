# File: pkg/doinst.sh
config() {
  NEW="$1"
  OLD="$(echo $NEW | sed 's/\.new$//')"
  # If the actual config file doesn't exist, move the .new one into place
  if [ ! -r $OLD ]; then
    mv $NEW $OLD
  elif [ "$(cat $OLD | md5sum)" = "$(cat $NEW | md5sum)" ]; then
    # If they are identical, just delete the redundant .new file
    rm $NEW
  fi
  # If they differ, the .new file is left in /etc for the user to diff manually
}

config etc/snapraidd.conf.new
