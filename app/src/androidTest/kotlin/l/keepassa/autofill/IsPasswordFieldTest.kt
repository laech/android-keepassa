package l.keepassa.autofill

import android.view.View.AUTOFILL_HINT_PASSWORD
import org.hamcrest.Matchers.equalTo
import org.junit.Assert.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import org.junit.runners.Parameterized.Parameters

@RunWith(Parameterized::class)
class IsPasswordFieldTest(
    private val isPasswordField: Boolean,
    private val view: Structure.View
) {

    @Test
    fun isPasswordField() {
        assertThat(view.isPasswordField(), equalTo(isPasswordField))
    }

    companion object {
        @JvmStatic
        @Parameters(name = "{0}, {1}")
        fun parameters() = listOf(
            arrayOf(false, emptyTextField),
            arrayOf(true, emptyTextField.copy(autofillHints = listOf(AUTOFILL_HINT_PASSWORD))),
            arrayOf(false, emptyTextField.copy(htmlInfo = htmlInput("date"))),
            arrayOf(true, emptyTextField.copy(htmlInfo = htmlInput("password"))),
            arrayOf(true, emptyTextField.copy(hint = "password")),
            arrayOf(true, emptyTextField.copy(hint = "Password")),
            arrayOf(true, emptyTextField.copy(hint = "Enter Password")),
            arrayOf(false, emptyTextField.copy(hint = "Age"))
        )
    }
}