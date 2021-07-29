PACKAGE_PATH=./
SRC=src
PLAT=unix64

lint:
	@find $(SRC) -iname "*.[ch]" | xargs -r clang-format -i -style=file
	@find $(PACKAGE_PATH) \( -iname "*.[ch]" -o -iname Makefile -o -iname CMakeLists.txt -o -iname README.md -o -iname config.in -o -iname "*.patch" -o -iname "*.pc.in" \) -executable | xargs -r chmod -x

cppcheck:
	@cppcheck --enable=all --force --platform=$(PLAT) -q $(SRC)

.PHONY: lint cppcheck
