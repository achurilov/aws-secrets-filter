package com.achurilov.secretsfilter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.maven.shared.filtering.DefaultMavenResourcesFiltering;
import org.apache.maven.shared.filtering.MavenFilteringException;
import org.apache.maven.shared.filtering.MavenResourcesExecution;
import org.apache.maven.shared.filtering.MavenResourcesFiltering;
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.interpolation.AbstractValueSource;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.util.Map;

import static org.codehaus.plexus.interpolation.StringSearchInterpolator.DEFAULT_END_EXPR;
import static org.codehaus.plexus.interpolation.StringSearchInterpolator.DEFAULT_START_EXPR;

@Component(role = MavenResourcesFiltering.class, hint = "awsSecretsFilter")
public class AwsSecretsFilter extends DefaultMavenResourcesFiltering {

    public final static String AWS_SECRETS_PROPERTY = "awsSecrets";
    public final static String AWS_REGION_PROPERTY = "awsRegion";
    public final static String AWS_REGION_DEFAULT = "eu-central-1";

    private String awsSecret;
    private String awsRegion;

    @Override
    public void filterResources(MavenResourcesExecution mavenResourcesExecution) throws MavenFilteringException {
        awsSecret = System.getProperty(AWS_SECRETS_PROPERTY);
        if (awsSecret != null) {
            awsRegion = System.getProperty(AWS_REGION_PROPERTY, AWS_REGION_DEFAULT);
            mavenResourcesExecution.addFilerWrapperWithEscaping(new AwsSecretValueSource(),
                    DEFAULT_START_EXPR, DEFAULT_END_EXPR, "\\", false);
        }
        super.filterResources(mavenResourcesExecution);
    }

    private class AwsSecretValueSource extends AbstractValueSource {

        private Map<String, Object> valuesMap;

        private AwsSecretValueSource() {
            super(false);
            SecretsManagerClient client = SecretsManagerClient.builder().region(Region.of(awsRegion)).build();
            GetSecretValueRequest valueRequest = GetSecretValueRequest.builder().secretId(awsSecret).build();
            GetSecretValueResponse valueResponse = client.getSecretValue(valueRequest);
            String secret = valueResponse.secretString();
            try {
                valuesMap = new ObjectMapper().readValue(secret, new TypeReference<Map<String,Object>>(){});
            } catch (JsonProcessingException e) {
                getLogger().error("Unexpected error", e);
            }
        }

        @Override
        public Object getValue(String key) {
            if (valuesMap != null && valuesMap.containsKey(key)) {
                return String.valueOf(valuesMap.get(key));
            } else {
                return null;
            }
        }

    }
}
