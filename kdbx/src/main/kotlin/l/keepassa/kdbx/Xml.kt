package l.keepassa.kdbx

import android.util.Xml
import com.google.common.collect.ImmutableList
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParser.*
import org.xmlpull.v1.XmlPullParserFactory
import org.xmlpull.v1.XmlSerializer
import java.io.InputStream
import java.io.StringWriter

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
        val writer = Xml.newSerializer()
        writer.setOutput(buffer)
        write(writer, 0)
        writer.flush()
        return buffer.toString()
    }

    operator fun get(name: String): Node? = when (value) {
        is Children -> value.children.find { it.name == name }
        else -> null
    }
}

private fun Node.write(writer: XmlSerializer, indent: Int) {
    writer.text("  ".repeat(indent))
    writer.startTag(null, name)

    attributes.forEach { (key, value) ->
        writer.attribute(null, key, value)
    }

    when (value) {
        is Text -> writer.text(value.text)
        is Children -> {
            value.children.forEach {
                writer.text("\n")
                it.write(writer, indent + 1)
            }
            writer.text("\n${"  ".repeat(indent)}")
        }
    }

    writer.endTag(null, name)
}

internal fun parseXml(input: InputStream): Node {
    val reader = XmlPullParserFactory.newInstance().newPullParser()
    reader.setInput(input, null)
    while (reader.next() != START_TAG) {
        reader.next()
    }
    return parseElement(reader)
}

private fun parseElement(input: XmlPullParser): Node {
    if (input.eventType != START_TAG) {
        throw IllegalStateException()
    }

    val name = input.name
    var text = ""
    val children = mutableListOf<Node>()
    val attributes = ImmutableList.copyOf((0 until input.attributeCount).map {
        Pair(input.getAttributeName(it), input.getAttributeValue(it))
    })

    while (input.next() != END_TAG) {
        when (input.eventType) {
            TEXT -> text = input.text
            START_TAG -> children.add(parseElement(input))
            else -> Unit
        }
    }

    return Node(
        name,
        attributes,
        when {
            children.size > 0 -> Children(ImmutableList.copyOf(children))
            text.isNotEmpty() -> Text(text)
            else -> null
        }
    )
}
