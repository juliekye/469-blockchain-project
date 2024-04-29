all: 
	dos2unix blockchain.py
	cp blockchain.py bchoc
	chmod +x bchoc

clean:
	rm bchoc
