package l.keepassa.autofill

import android.view.View.AUTOFILL_HINT_EMAIL_ADDRESS
import android.view.View.AUTOFILL_HINT_USERNAME
import org.hamcrest.Matchers.equalTo
import org.junit.Assert.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import org.junit.runners.Parameterized.Parameters

@RunWith(Parameterized::class)
class IsUsernameFieldTest(
    private val isUsernameField: Boolean,
    private val view: Structure.View
) {

    @Test
    fun isUsernameField() {
        assertThat(view.isUsernameField(), equalTo(isUsernameField))
    }

    companion object {
        @JvmStatic
        @Parameters(name = "{0}, {1}")
        fun parameters() = listOf(
            arrayOf(false, emptyTextField),
            arrayOf(true, emptyTextField.copy(autofillHints = listOf(AUTOFILL_HINT_USERNAME))),
            arrayOf(true, emptyTextField.copy(autofillHints = listOf(AUTOFILL_HINT_EMAIL_ADDRESS))),
            arrayOf(false, emptyTextField.copy(htmlInfo = htmlInput("date"))),
            arrayOf(true, emptyTextField.copy(htmlInfo = htmlInput("email"))),
            arrayOf(true, emptyTextField.copy(hint = "username")),
            arrayOf(true, emptyTextField.copy(hint = "Username")),
            arrayOf(true, emptyTextField.copy(hint = "email")),
            arrayOf(true, emptyTextField.copy(hint = "Email")),
            arrayOf(true, emptyTextField.copy(hint = "Enter Email")),
            arrayOf(false, emptyTextField.copy(hint = "Age"))
        )
    }
}