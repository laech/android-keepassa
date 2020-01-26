package kdbx

import com.google.common.collect.ImmutableList
import java.io.InputStream
import java.io.StringWriter
import javax.xml.XMLConstants
import javax.xml.stream.*

internal sealed class Value
internal data class Text(val text: String) : Value()
internal data class Children(val children: ImmutableList<Node>) : Value()

internal data class Node(
    val name: String,
    val attributes: ImmutableList<Pair<String, String>>,
    val value: Value?
) {
    override fun toString(): String {
        val buffer = StringWriter()
        val writer = XMLOutputFactory
            .newDefaultFactory()
            .createXMLStreamWriter(buffer)
        write(writer, 0)
        writer.flush()
        return buffer.toString()
    }
}

private fun Node.write(writer: XMLStreamWriter, indent: Int) {
    writer.writeCharacters("  ".repeat(indent))

    if (value == null) {
        writer.writeEmptyElement(name)
    } else {
        writer.writeStartElement(name)
    }

    attributes.forEach { (key, value) ->
        writer.writeAttribute(key, value)
    }

    when (value) {
        is Text -> writer.writeCharacters(value.text)
        is Children -> {
            value.children.forEach {
                writer.writeCharacters("\n")
                it.write(writer, indent + 1)
            }
            writer.writeCharacters("\n${"  ".repeat(indent)}")
        }
    }

    if (value != null) {
        writer.writeEndElement()
    }
}


private fun newStreamReader(input: InputStream): XMLStreamReader {
    val factory = XMLInputFactory.newDefaultFactory()
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "")
    factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")
    factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    factory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false)
    factory.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, false)
    factory.setProperty(XMLInputFactory.IS_VALIDATING, false)
    factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    return factory.createXMLStreamReader(input)
}

internal fun parseXml(input: InputStream): Node {
    val reader = newStreamReader(input)
    while (reader.next() != XMLStreamConstants.START_ELEMENT) {
        reader.next()
    }
    return parseElement(reader)
}

private fun parseElement(input: XMLStreamReader): Node {
    if (input.eventType != XMLStreamConstants.START_ELEMENT) {
        throw IllegalStateException()
    }

    val name = input.localName
    var text = ""
    val children = mutableListOf<Node>()
    val attributes = ImmutableList.copyOf((0 until input.attributeCount).map {
        Pair(input.getAttributeLocalName(it), input.getAttributeValue(it))
    })

    while (input.hasNext()) {
        when (input.next()) {
            XMLStreamConstants.CHARACTERS,
            XMLStreamConstants.CDATA -> if (!input.isWhiteSpace) {
                text = input.text
            }
            XMLStreamConstants.START_ELEMENT -> {
                children.add(parseElement(input))
            }
            XMLStreamConstants.END_ELEMENT -> return Node(
                name,
                attributes,
                when {
                    children.size > 0 -> Children(ImmutableList.copyOf(children))
                    text.isNotEmpty() -> Text(text)
                    else -> null
                }
            )
            else -> {
            }
        }
    }

    throw XMLStreamException("Invalid XML")
}
