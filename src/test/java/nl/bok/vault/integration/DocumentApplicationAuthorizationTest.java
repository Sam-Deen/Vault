package nl.bok.vault.integration;

import nl.bok.vault.entity.*;
import nl.bok.vault.repository.*;
import nl.bok.vault.security.CurrentUser;
import nl.bok.vault.service.*;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
import java.time.Instant;
import java.util.Optional;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;

/** Tests application guards with an unfiltered repository, independently of RLS. */
class DocumentApplicationAuthorizationTest {
    @Test void unfilteredRepositoryCannotBypassApplicationTenantAndPermissionGuards() {
        var documents = mock(DocumentRepository.class);
        var permissions = mock(DocumentPermissionRepository.class);
        var identity = mock(CurrentUser.class);
        var a = new Organization(1L,"A"); var b = new Organization(2L,"B");
        var alice = new VaultUser(1L,"alice","unused",a,Role.EMPLOYEE);
        var bob = new VaultUser(2L,"bob","unused",a,Role.EMPLOYEE);
        var charlie = new VaultUser(4L,"charlie","unused",b,Role.EMPLOYEE);
        when(identity.get()).thenReturn(alice);
        when(documents.findById(1L)).thenReturn(Optional.of(new Document(1L,a,alice,"own","own",Instant.EPOCH)));
        when(documents.findById(2L)).thenReturn(Optional.of(new Document(2L,a,bob,"secret","secret",Instant.EPOCH)));
        when(documents.findById(3L)).thenReturn(Optional.of(new Document(3L,b,charlie,"secret","secret",Instant.EPOCH)));
        var service = new DocumentService(documents,identity,new DocumentAuthorization(permissions),new SecurityAudit());
        assertThat(service.getById(1L).id()).isEqualTo(1L);
        for (long id : new long[]{2,3}) {
            assertThatThrownBy(() -> service.getById(id)).isInstanceOfSatisfying(ResponseStatusException.class,
                    error -> assertThat(error.getStatusCode().value()).isEqualTo(404));
        }
        verify(permissions,never()).findByDocumentIdAndUserId(3L,1L);
    }
}
