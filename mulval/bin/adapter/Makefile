LIBS=${MULVALROOT}/lib/dom4j-2.1.3.jar:${MULVALROOT}/lib/jaxen-1.1.1.jar:${MULVALROOT}/lib/json-simple-1.1.1.jar:${MULVALROOT}/lib/mysql-connector-java-8.0.27.jar
TARGET=GetCVEID.class GetTplQry.class InitializeDB.class MetricParser.class NessusXMLParser.class GetTplQry_nessusXML.class XMLConstructor.class mysqlConnectionChecker.class 

.SUFFIXES: .java .class

default: ${TARGET}

.java.class:
	javac $*.java -cp ${CLASSPATH}:${LIBS}

install: ${TARGET}
	cp ${TARGET} ../../bin/adapter

clean:
	rm -f *.class
