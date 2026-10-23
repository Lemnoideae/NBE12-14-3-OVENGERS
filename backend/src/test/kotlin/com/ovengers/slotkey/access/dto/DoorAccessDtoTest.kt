package com.ovengers.slotkey.access.dto

import com.ovengers.slotkey.access.dto.request.DoorAccessVerifyRequest
import com.ovengers.slotkey.access.dto.response.DoorAccessTokenResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.LocalDateTime

class DoorAccessDtoTest {
    @Test
    @DisplayName("출입 검증 요청의 문자열 표현은 원문 토큰을 숨기고 실제 값은 보존한다")
    fun masksRequestTokenInStringRepresentation() {
        val rawToken = "sensitive-door-request-token"
        val request = DoorAccessVerifyRequest(10L, rawToken)
        assertThat(request.toString()).doesNotContain(rawToken).contains("[REDACTED]")
        assertThat(request.token).isEqualTo(rawToken)
    }

    @Test
    @DisplayName("출입 토큰 응답의 문자열 표현은 원문 토큰을 숨기고 실제 값은 보존한다")
    fun masksResponseTokenInStringRepresentation() {
        val rawToken = "sensitive-door-response-token"
        val response = DoorAccessTokenResponse.of(101L, rawToken, LocalDateTime.of(2026, 10, 23, 14, 0))
        assertThat(response.toString()).doesNotContain(rawToken).contains("[REDACTED]")
        assertThat(response.token).isEqualTo(rawToken)
    }
}
