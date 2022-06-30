
while [ 1 ]
do
	if [ -f './zipfile' ];then
		ls -ltr
		echo "zip exists"
		unzip -o zipfile
		ls -ltr 
		rm -f './zipfile'
	elif [ -f './tarfile' ];then
		ls -ltr
		echo "tar exists"
		tar xvf 'tarfile'
		ls -ltr 
		rm -f './tarfile'
	fi
done

