package aws

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
)

func resourceAwsLbListener() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsLbListenerCreate,
		Read:   resourceAwsLbListenerRead,
		Update: resourceAwsLbListenerUpdate,
		Delete: resourceAwsLbListenerDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"load_balancer_arn": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"port": {
				Type:         schema.TypeInt,
				Required:     true,
				ValidateFunc: validation.IntBetween(1, 65535),
			},

			"protocol": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "HTTP",
				StateFunc: func(v interface{}) string {
					return strings.ToUpper(v.(string))
				},
				ValidateFunc: validateLbListenerProtocol(),
			},

			"ssl_policy": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},

			"certificate_arn": {
				Type:     schema.TypeString,
				Optional: true,
			},

			"default_action": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"target_group_arn": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"type": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validateLbListenerActionType(),
						},
						"order": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntBetween(1, 50000),
						},
						"authenticate_cognito_config": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"authentication_request_extra_params": {
										Type:     schema.TypeMap,
										Optional: true,
									},
									"on_unauthenticated_request": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
										ValidateFunc: validation.StringInSlice([]string{
											elbv2.AuthenticateCognitoActionConditionalBehaviorEnumDeny,
											elbv2.AuthenticateCognitoActionConditionalBehaviorEnumAllow,
											elbv2.AuthenticateCognitoActionConditionalBehaviorEnumAuthenticate,
										}, true),
									},
									"scope": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"session_cookie_name": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"session_timeout": {
										Type:     schema.TypeInt,
										Optional: true,
										Computed: true,
									},
									"user_pool_arn": {
										Type:     schema.TypeString,
										Required: true,
									},
									"user_pool_client": {
										Type:     schema.TypeString,
										Required: true,
									},
									"user_pool_domain": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
						"authenticate_oidc_config": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"authentication_request_extra_params": {
										Type:     schema.TypeMap,
										Optional: true,
									},
									"authorization_endpoint": {
										Type:     schema.TypeString,
										Required: true,
									},
									"client_id": {
										Type:     schema.TypeString,
										Required: true,
									},
									"client_secret": {
										Type:      schema.TypeString,
										Required:  true,
										Sensitive: true,
									},
									"issuer": {
										Type:     schema.TypeString,
										Required: true,
									},
									"on_unauthenticated_request": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
										ValidateFunc: validation.StringInSlice([]string{
											elbv2.AuthenticateOidcActionConditionalBehaviorEnumDeny,
											elbv2.AuthenticateOidcActionConditionalBehaviorEnumAllow,
											elbv2.AuthenticateOidcActionConditionalBehaviorEnumAuthenticate,
										}, true),
									},
									"scope": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"session_cookie_name": {
										Type:     schema.TypeString,
										Optional: true,
										Computed: true,
									},
									"session_timeout": {
										Type:     schema.TypeInt,
										Optional: true,
										Computed: true,
									},
									"token_endpoint": {
										Type:     schema.TypeString,
										Required: true,
									},
									"user_info_endpoint": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func resourceAwsLbListenerCreate(d *schema.ResourceData, meta interface{}) error {
	elbconn := meta.(*AWSClient).elbv2conn

	lbArn := d.Get("load_balancer_arn").(string)

	params := &elbv2.CreateListenerInput{
		LoadBalancerArn: aws.String(lbArn),
		Port:            aws.Int64(int64(d.Get("port").(int))),
		Protocol:        aws.String(d.Get("protocol").(string)),
	}

	if sslPolicy, ok := d.GetOk("ssl_policy"); ok {
		params.SslPolicy = aws.String(sslPolicy.(string))
	}

	if certificateArn, ok := d.GetOk("certificate_arn"); ok {
		params.Certificates = make([]*elbv2.Certificate, 1)
		params.Certificates[0] = &elbv2.Certificate{
			CertificateArn: aws.String(certificateArn.(string)),
		}
	}

	if defaultActions := d.Get("default_action").([]interface{}); len(defaultActions) > 0 {
		params.DefaultActions = make([]*elbv2.Action, len(defaultActions))

		for i, defaultAction := range defaultActions {
			defaultActionMap := defaultAction.(map[string]interface{})

			actionType := defaultActionMap["type"].(string)
			action := &elbv2.Action{
				Type: aws.String(actionType),
			}
			if v, ok := defaultActionMap["order"].(int); ok && v != 0 {
				action.Order = aws.Int64(int64(v))
			}

			switch actionType {
			case elbv2.ActionTypeEnumForward:
				if v, ok := defaultActionMap["target_group_arn"].(string); ok && v != "" {
					action.TargetGroupArn = aws.String(v)
				}
			case elbv2.ActionTypeEnumAuthenticateOidc:
				if v, ok := defaultActionMap["authenticate_oidc_config"].([]interface{}); ok {
					action.AuthenticateOidcConfig = expandELbAuthenticateOidcActionConfig(v[0].(map[string]interface{}))
				}
			case elbv2.ActionTypeEnumAuthenticateCognito:
				if v, ok := defaultActionMap["authenticate_cognito_config"].([]interface{}); ok {
					action.AuthenticateCognitoConfig = expandELbAuthenticateCognitoActionConfig(v[0].(map[string]interface{}))
				}
			}

			params.DefaultActions[i] = action
		}
	}

	var resp *elbv2.CreateListenerOutput

	err := resource.Retry(5*time.Minute, func() *resource.RetryError {
		var err error
		log.Printf("[DEBUG] Creating LB listener for ARN: %s", d.Get("load_balancer_arn").(string))
		resp, err = elbconn.CreateListener(params)
		if err != nil {
			if isAWSErr(err, elbv2.ErrCodeCertificateNotFoundException, "") {
				return resource.RetryableError(err)
			}
			return resource.NonRetryableError(err)
		}
		return nil
	})

	if err != nil {
		return errwrap.Wrapf("Error creating LB Listener: {{err}}", err)
	}

	if len(resp.Listeners) == 0 {
		return errors.New("Error creating LB Listener: no listeners returned in response")
	}

	d.SetId(*resp.Listeners[0].ListenerArn)

	return resourceAwsLbListenerRead(d, meta)
}

func resourceAwsLbListenerRead(d *schema.ResourceData, meta interface{}) error {
	elbconn := meta.(*AWSClient).elbv2conn

	resp, err := elbconn.DescribeListeners(&elbv2.DescribeListenersInput{
		ListenerArns: []*string{aws.String(d.Id())},
	})
	if err != nil {
		if isAWSErr(err, elbv2.ErrCodeListenerNotFoundException, "") {
			log.Printf("[WARN] DescribeListeners - removing %s from state", d.Id())
			d.SetId("")
			return nil
		}
		return errwrap.Wrapf("Error retrieving Listener: {{err}}", err)
	}

	if len(resp.Listeners) != 1 {
		return fmt.Errorf("Error retrieving Listener %q", d.Id())
	}

	listener := resp.Listeners[0]

	d.Set("arn", listener.ListenerArn)
	d.Set("load_balancer_arn", listener.LoadBalancerArn)
	d.Set("port", listener.Port)
	d.Set("protocol", listener.Protocol)
	d.Set("ssl_policy", listener.SslPolicy)

	if listener.Certificates != nil && len(listener.Certificates) == 1 {
		d.Set("certificate_arn", listener.Certificates[0].CertificateArn)
	}

	sortedActions := sortActionsBasedonTypeinTFFile(listener.DefaultActions, d)
	flattenElbActions := make([]interface{}, 0, len(sortedActions))
	for i, action := range sortedActions {
		m := make(map[string]interface{})
		if action.Order != nil {
			m["order"] = int(aws.Int64Value(action.Order))
		}
		actionType := aws.StringValue(action.Type)
		m["type"] = actionType

		switch actionType {
		case elbv2.ActionTypeEnumForward:
			m["target_group_arn"] = aws.StringValue(action.TargetGroupArn)
		case elbv2.ActionTypeEnumAuthenticateOidc:
			// Since the client_secret is never returned from the API ignore it and use whats already in the state
			client_secret := d.Get("default_action." + strconv.Itoa(i) + ".authenticate_oidc_config.0.client_secret").(string)
			m["authenticate_oidc_config"] = flattenELbAuthenticateOidcActionConfig(action.AuthenticateOidcConfig, client_secret)
		case elbv2.ActionTypeEnumAuthenticateCognito:
			m["authenticate_cognito_config"] = flattenELbAuthenticateCognitoActionConfig(action.AuthenticateCognitoConfig)
		}
		flattenElbActions = append(flattenElbActions, m)
	}

	if err := d.Set("default_action", flattenElbActions); err != nil {
		return err
	}

	return nil
}

func sortActionsBasedonTypeinTFFile(actions []*elbv2.Action, d *schema.ResourceData) []*elbv2.Action {
	actionCount := d.Get("default_action.#").(int)
	for i := 0; i < actionCount; i++ {
		currAction := d.Get("default_action." + strconv.Itoa(i)).(map[string]interface{})
		for j, action := range actions {
			if currAction["type"].(string) == aws.StringValue(action.Type) {
				actions[i], actions[j] = actions[j], actions[i]
			}
		}
	}
	return actions
}

func resourceAwsLbListenerUpdate(d *schema.ResourceData, meta interface{}) error {
	elbconn := meta.(*AWSClient).elbv2conn

	params := &elbv2.ModifyListenerInput{
		ListenerArn: aws.String(d.Id()),
		Port:        aws.Int64(int64(d.Get("port").(int))),
		Protocol:    aws.String(d.Get("protocol").(string)),
	}

	if sslPolicy, ok := d.GetOk("ssl_policy"); ok {
		params.SslPolicy = aws.String(sslPolicy.(string))
	}

	if certificateArn, ok := d.GetOk("certificate_arn"); ok {
		params.Certificates = make([]*elbv2.Certificate, 1)
		params.Certificates[0] = &elbv2.Certificate{
			CertificateArn: aws.String(certificateArn.(string)),
		}
	}

	if defaultActions := d.Get("default_action").([]interface{}); len(defaultActions) > 0 {
		params.DefaultActions = make([]*elbv2.Action, len(defaultActions))

		for i, defaultAction := range defaultActions {
			defaultActionMap := defaultAction.(map[string]interface{})

			actionType := defaultActionMap["type"].(string)
			action := &elbv2.Action{
				Type: aws.String(actionType),
			}
			if v, ok := defaultActionMap["order"].(int); ok && v != 0 {
				action.Order = aws.Int64(int64(v))
			}

			switch actionType {
			case elbv2.ActionTypeEnumForward:
				if v, ok := defaultActionMap["target_group_arn"].(string); ok && v != "" {
					action.TargetGroupArn = aws.String(v)
				}
			case elbv2.ActionTypeEnumAuthenticateOidc:
				if v, ok := defaultActionMap["authenticate_oidc_config"].([]interface{}); ok {
					action.AuthenticateOidcConfig = expandELbAuthenticateOidcActionConfig(v[0].(map[string]interface{}))
				}
			case elbv2.ActionTypeEnumAuthenticateCognito:
				if v, ok := defaultActionMap["authenticate_cognito_config"].([]interface{}); ok {
					action.AuthenticateCognitoConfig = expandELbAuthenticateCognitoActionConfig(v[0].(map[string]interface{}))
				}
			}

			params.DefaultActions[i] = action
		}
	}

	err := resource.Retry(5*time.Minute, func() *resource.RetryError {
		_, err := elbconn.ModifyListener(params)
		if err != nil {
			if isAWSErr(err, elbv2.ErrCodeCertificateNotFoundException, "") {
				return resource.RetryableError(err)
			}
			return resource.NonRetryableError(err)
		}
		return nil
	})
	if err != nil {
		return errwrap.Wrapf("Error modifying LB Listener: {{err}}", err)
	}

	return resourceAwsLbListenerRead(d, meta)
}

func resourceAwsLbListenerDelete(d *schema.ResourceData, meta interface{}) error {
	elbconn := meta.(*AWSClient).elbv2conn

	_, err := elbconn.DeleteListener(&elbv2.DeleteListenerInput{
		ListenerArn: aws.String(d.Id()),
	})
	if err != nil {
		return errwrap.Wrapf("Error deleting Listener: {{err}}", err)
	}

	return nil
}

func validateLbListenerActionType() schema.SchemaValidateFunc {
	return validation.StringInSlice([]string{
		elbv2.ActionTypeEnumForward,
		elbv2.ActionTypeEnumAuthenticateOidc,
		elbv2.ActionTypeEnumAuthenticateCognito,
	}, true)
}

func validateLbListenerProtocol() schema.SchemaValidateFunc {
	return validation.StringInSlice([]string{
		"http",
		"https",
		"tcp",
	}, true)
}

func expandELbAuthenticateCognitoActionConfig(cfg map[string]interface{}) *elbv2.AuthenticateCognitoActionConfig {
	if len(cfg) == 0 {
		return nil
	}
	result := &elbv2.AuthenticateCognitoActionConfig{
		UserPoolArn:      aws.String(cfg["user_pool_arn"].(string)),
		UserPoolClientId: aws.String(cfg["user_pool_client"].(string)),
		UserPoolDomain:   aws.String(cfg["user_pool_domain"].(string)),
	}

	if v, ok := cfg["authentication_request_extra_params"]; ok {
		params := make(map[string]*string)

		for key, value := range v.(map[string]interface{}) {
			params[key] = aws.String(value.(string))
		}
		result.AuthenticationRequestExtraParams = params
	}
	if v, ok := cfg["on_unauthenticated_request"].(string); ok && v != "" {
		result.OnUnauthenticatedRequest = aws.String(v)
	}
	if v, ok := cfg["scope"].(string); ok && v != "" {
		result.Scope = aws.String(v)
	}
	if v, ok := cfg["session_cookie_name"].(string); ok && v != "" {
		result.SessionCookieName = aws.String(v)
	}
	if v, ok := cfg["session_timeout"].(int); ok && v != 0 {
		result.SessionTimeout = aws.Int64(int64(v))
	}

	return result
}

func expandELbAuthenticateOidcActionConfig(cfg map[string]interface{}) *elbv2.AuthenticateOidcActionConfig {
	if len(cfg) == 0 {
		return nil
	}
	result := &elbv2.AuthenticateOidcActionConfig{
		AuthorizationEndpoint: aws.String(cfg["authorization_endpoint"].(string)),
		ClientId:              aws.String(cfg["client_id"].(string)),
		ClientSecret:          aws.String(cfg["client_secret"].(string)),
		Issuer:                aws.String(cfg["issuer"].(string)),
		TokenEndpoint:         aws.String(cfg["token_endpoint"].(string)),
		UserInfoEndpoint:      aws.String(cfg["user_info_endpoint"].(string)),
	}

	if v, ok := cfg["authentication_request_extra_params"]; ok {
		params := make(map[string]*string)

		for key, value := range v.(map[string]interface{}) {
			params[key] = aws.String(value.(string))
		}
		result.AuthenticationRequestExtraParams = params
	}
	if v, ok := cfg["on_unauthenticated_request"].(string); ok && v != "" {
		result.OnUnauthenticatedRequest = aws.String(v)
	}
	if v, ok := cfg["scope"].(string); ok && v != "" {
		result.Scope = aws.String(v)
	}
	if v, ok := cfg["session_cookie_name"].(string); ok && v != "" {
		result.SessionCookieName = aws.String(v)
	}
	if v, ok := cfg["session_timeout"].(int); ok && v != 0 {
		result.SessionTimeout = aws.Int64(int64(v))
	}

	return result
}

func flattenELbAuthenticateOidcActionConfig(cfg *elbv2.AuthenticateOidcActionConfig, client_secret string) []map[string]interface{} {
	if cfg == nil {
		return nil
	}
	m := make(map[string]interface{})

	m["authorization_endpoint"] = aws.StringValue(cfg.AuthorizationEndpoint)
	m["client_id"] = aws.StringValue(cfg.ClientId)
	m["client_secret"] = client_secret
	m["issuer"] = aws.StringValue(cfg.Issuer)
	m["on_unauthenticated_request"] = aws.StringValue(cfg.OnUnauthenticatedRequest)
	m["scope"] = aws.StringValue(cfg.Scope)
	m["session_cookie_name"] = aws.StringValue(cfg.SessionCookieName)
	m["session_timeout"] = aws.Int64Value(cfg.SessionTimeout)
	m["token_endpoint"] = aws.StringValue(cfg.TokenEndpoint)
	m["user_info_endpoint"] = aws.StringValue(cfg.UserInfoEndpoint)

	if len(cfg.AuthenticationRequestExtraParams) > 0 {
		params := make(map[string]interface{})
		for k, v := range cfg.AuthenticationRequestExtraParams {
			params[k] = aws.StringValue(v)
		}
		m["authentication_request_extra_params"] = params
	}

	return []map[string]interface{}{m}
}

func flattenELbAuthenticateCognitoActionConfig(cfg *elbv2.AuthenticateCognitoActionConfig) []map[string]interface{} {
	if cfg == nil {
		return nil
	}
	m := make(map[string]interface{})

	m["on_unauthenticated_request"] = aws.StringValue(cfg.OnUnauthenticatedRequest)
	m["scope"] = aws.StringValue(cfg.Scope)
	m["session_cookie_name"] = aws.StringValue(cfg.SessionCookieName)
	m["session_timeout"] = aws.Int64Value(cfg.SessionTimeout)
	m["user_pool_arn"] = aws.StringValue(cfg.UserPoolArn)
	m["user_pool_client"] = aws.StringValue(cfg.UserPoolClientId)
	m["user_pool_domain"] = aws.StringValue(cfg.UserPoolDomain)

	if len(cfg.AuthenticationRequestExtraParams) > 0 {
		params := make(map[string]interface{})
		for k, v := range cfg.AuthenticationRequestExtraParams {
			params[k] = aws.StringValue(v)
		}
		m["authentication_request_extra_params"] = params
	}

	return []map[string]interface{}{m}
}
