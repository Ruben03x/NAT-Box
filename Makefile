# Define the Java compiler
JAVAC = javac

# Define the Java compiler flags
JAVACFLAGS = -d bin

# Define the directory where your source files are located
SRCDIR = src/project3

# Define the directory where your compiled .class files will be placed
BINDIR = bin

# Define the source files
SOURCES := $(wildcard $(SRCDIR)/*.java)

# Define the class files by replacing .java extension with .class
CLASSES := $(SOURCES:$(SRCDIR)/%.java=$(BINDIR)/%.class)

# Define the default target
default: all

# Define the target for compiling all Java files
all: $(CLASSES)

# Define a pattern rule for compiling .java files into .class files
$(BINDIR)/%.class: $(SRCDIR)/%.java
	$(JAVAC) $(JAVACFLAGS) $<

# Define a target for running NAT
nat: $(BINDIR)/NAT.class
	java -cp $(BINDIR) project3.NAT

# Define a target for running Client
client: $(BINDIR)/Client.class
	java -cp $(BINDIR) project3.Client

# Define a target for cleaning up compiled files
clean:
	rm -f $(BINDIR)/*.class