test:
	ruby -Ilib tests/test_vcert.rb -v



publish:
	rm -rf vcert*gem
	gem build vcert.gemspec
	gem push vcert*gem
