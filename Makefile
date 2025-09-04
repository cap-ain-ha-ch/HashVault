JAVAC = javac
JAVA = java
JAR = lib/sqlite-jdbc-3.50.3.0.jar
SRC_DIR = src
BIN_DIR = bin
CLASSPATH = $(JAR):$(BIN_DIR)

SOURCES = $(wildcard $(SRC_DIR)/*.java)
CLASSES = $(SOURCES:$(SRC_DIR)/%.java=$(BIN_DIR)/%.class)

.PHONY: all run clean

all:
	@mkdir -p $(BIN_DIR)
	$(JAVAC) -cp $(JAR) -d $(BIN_DIR) $(SRC_DIR)/*.java

run: all
	$(JAVA) -cp $(CLASSPATH) Main $(ARGS)

clean:
	rm -rf $(BIN_DIR)
