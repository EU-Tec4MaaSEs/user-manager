package gr.atc.t4m.events;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEvent;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Organization Deletion Event Tests")
class OrganizationDeletionEventTests {

    @Test
    @DisplayName("Create Event : Success")
    void givenSourceAndPilotName_whenCreateEvent_thenEventCreated() {
        // Given
        Object source = new Object();
        String pilotName = "TEST_PILOT";

        // When
        OrganizationDeletionEvent event = new OrganizationDeletionEvent(source, pilotName);

        // Then
        assertThat(event).isInstanceOf(ApplicationEvent.class);
        assertThat(event.getPilotName()).isEqualTo(pilotName);
        assertThat(event.getSource()).isEqualTo(source);
    }

    @Test
    @DisplayName("Create Event : With Null Pilot Name")
    void givenNullPilotName_whenCreateEvent_thenEventCreatedWithNull() {
        // Given
        Object source = new Object();
        String pilotName = null;

        // When
        OrganizationDeletionEvent event = new OrganizationDeletionEvent(source, pilotName);

        // Then
        assertThat(event.getPilotName()).isNull();
        assertThat(event.getSource()).isEqualTo(source);
    }

    @Test
    @DisplayName("Create Event : With Empty Pilot Name")
    void givenEmptyPilotName_whenCreateEvent_thenEventCreatedWithEmpty() {
        // Given
        Object source = new Object();
        String pilotName = "";

        // When
        OrganizationDeletionEvent event = new OrganizationDeletionEvent(source, pilotName);

        // Then
        assertThat(event.getPilotName()).isEmpty();
        assertThat(event.getSource()).isEqualTo(source);
    }
}