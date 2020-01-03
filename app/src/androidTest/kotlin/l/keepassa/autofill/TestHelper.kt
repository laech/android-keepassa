package l.keepassa.autofill

import android.os.Parcel
import android.util.Pair
import android.view.View.AUTOFILL_TYPE_TEXT
import android.view.ViewStructure
import android.view.autofill.AutofillId
import org.mockito.BDDMockito.given
import org.mockito.Mockito.mock

val dummyAutofillId: AutofillId = Parcel.obtain().run {
    writeInt(1)
    writeInt(2)
    AutofillId.CREATOR.createFromParcel(this)
}

val emptyTextField = Structure.View(
    dummyAutofillId,
    AUTOFILL_TYPE_TEXT,
    emptyList(),
    null,
    null,
    null,
    null,
    emptySequence()
)

fun htmlInput(type: String): ViewStructure.HtmlInfo {
    val html = mock(ViewStructure.HtmlInfo::class.java)
    given(html.tag).willReturn("input")
    given(html.attributes).willReturn(listOf(Pair("type", type)))
    return html
}
