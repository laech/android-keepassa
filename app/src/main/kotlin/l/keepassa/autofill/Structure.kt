package l.keepassa.autofill

import android.app.assist.AssistStructure
import android.view.View.*
import android.view.ViewStructure
import android.view.autofill.AutofillId
import java.util.Locale.ENGLISH

// Wrapper classes for AssistedStructure, AssistedStructure.WindowNode,
// and AssistedStructure.ViewNode, to make things testable as the original
// classes can't be instantiated easily for testing.

data class Structure(
    val children: Sequence<Window>
) {
    constructor(source: AssistStructure) : this(
        children = (0 until source.windowNodeCount)
            .asSequence()
            .map(source::getWindowNodeAt)
            .map(::Window)
    )

    data class Window(
        val title: String?,
        val views: Sequence<View>
    ) {
        constructor(source: AssistStructure.WindowNode) : this(
            title = source.title.toString(),
            views = (0 until source.rootViewNode.childCount)
                .asSequence()
                .map(source.rootViewNode::getChildAt)
                .map(::View)
        )

        fun extractPackageIdFromTitle(): String? = title?.split('/')?.get(0)

        fun textFields(): Sequence<View> =
            views.flatMap(View::leaves).filter { it.autofillType == AUTOFILL_TYPE_TEXT }
    }

    data class View(
        val autofillId: AutofillId?,
        val autofillType: Int,
        val autofillHints: List<String>,
        val htmlInfo: ViewStructure.HtmlInfo?,
        val hint: String?,
        val webDomain: String?,
        val packageId: String?,
        val children: Sequence<View>
    ) {
        constructor(source: AssistStructure.ViewNode) : this(
            autofillId = source.autofillId,
            autofillType = source.autofillType,
            autofillHints = source.autofillHints?.asList() ?: emptyList(),
            htmlInfo = source.htmlInfo,
            hint = source.hint,
            webDomain = source.webDomain,
            packageId = source.idPackage,
            children = (0 until source.childCount)
                .asSequence()
                .map(source::getChildAt)
                .map(::View)
        )

        fun leaves(): Sequence<View> =
            children.flatMap(View::leaves).ifEmpty { sequenceOf(this) }

        fun isUsernameField() = when {
            autofillId == null -> false
            autofillType != AUTOFILL_TYPE_TEXT -> false
            autofillHints.any(usernameAutofillHints::contains) -> true
            htmlInfo.isInputType("email") -> true
            hint.anyMatch(usernameDisplayHints) -> true
            else -> false
        }

        fun isPasswordField() = when {
            autofillId == null -> false
            autofillType != AUTOFILL_TYPE_TEXT -> false
            autofillHints.any { it == AUTOFILL_HINT_PASSWORD } -> true
            htmlInfo.isInputType("password") -> true
            hint.anyMatch(passwordDisplayHints) -> true
            else -> false
        }
    }
}

private val usernameAutofillHints = setOf(
    AUTOFILL_HINT_USERNAME,
    AUTOFILL_HINT_EMAIL_ADDRESS
)

// TODO translations?
private val usernameDisplayHints = setOf("username", "email")
private val passwordDisplayHints = setOf("password")

private fun String?.anyMatch(values: Set<String>): Boolean {
    val str = this?.toLowerCase(ENGLISH)?.trim() ?: return false
    return values.contains(str) || values.any { str.contains(it) }
}

private fun ViewStructure.HtmlInfo?.isInputType(type: String) =
    this?.tag == "input" && this.attributes?.any {
        it.first == "type" && it.second == type
    } == true
