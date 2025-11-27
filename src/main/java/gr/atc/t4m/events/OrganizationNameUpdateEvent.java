package gr.atc.t4m.events;

import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class OrganizationNameUpdateEvent extends ApplicationEvent {
    private final String pilotName;

    public OrganizationNameUpdateEvent(Object source, String pilotName) {
        super(source);
        this.pilotName = pilotName;
    }
}
