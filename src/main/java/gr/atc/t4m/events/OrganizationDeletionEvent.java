package gr.atc.t4m.events;

import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class OrganizationDeletionEvent extends ApplicationEvent {
    private final String pilotName;

    public OrganizationDeletionEvent(Object source, String pilotName) {
        super(source);
        this.pilotName = pilotName;
    }
}
